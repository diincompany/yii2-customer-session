<?php

namespace diincompany\customersession\components;

use diincompany\customersession\contracts\CustomerSessionInterface;
use diincompany\customersession\dto\CustomerIdentity;
use diincompany\customersession\exceptions\CustomerSessionException;
use GuzzleHttp\Client;
use Yii;
use yii\base\Component;
use yii\helpers\Json;
use yii\web\Response;

class Auth0CustomerSession extends Component implements CustomerSessionInterface
{
    public string $domain = '';
    public string $clientId = '';
    public string $clientSecret = '';
    public string $redirectUri = '';
    public string $audience = '';
    public string $scope = 'openid profile email';
    public string $identitySessionKey = '__customer_identity';
    public string $stateSessionKey = '__customer_oidc_state';
    public string $nonceSessionKey = '__customer_oidc_nonce';
    public string $codeVerifierSessionKey = '__customer_oidc_code_verifier';
    public string $returnUrlSessionKey = '__customer_oidc_return_url';

    public function isGuest(): bool
    {
        return $this->getIdentity() === null;
    }

    public function getIdentity(): ?CustomerIdentity
    {
        $identity = Yii::$app->session->get($this->identitySessionKey);

        if (!is_array($identity)) {
            return null;
        }

        $customerIdentity = CustomerIdentity::fromArray($identity);

        return $customerIdentity->authSubject !== '' ? $customerIdentity : null;
    }

    public function login(string $returnUrl): Response
    {
        $this->validateConfiguration();

        $state = $this->randomUrlSafeString(32);
        $nonce = $this->randomUrlSafeString(32);
        $codeVerifier = $this->randomUrlSafeString(64);

        Yii::$app->session->set($this->stateSessionKey, $state);
        Yii::$app->session->set($this->nonceSessionKey, $nonce);
        Yii::$app->session->set($this->codeVerifierSessionKey, $codeVerifier);
        Yii::$app->session->set($this->returnUrlSessionKey, $returnUrl);

        $params = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => $this->scope,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $this->base64UrlEncode(hash('sha256', $codeVerifier, true)),
            'code_challenge_method' => 'S256',
        ];

        if ($this->audience !== '') {
            $params['audience'] = $this->audience;
        }

        return Yii::$app->response->redirect($this->auth0Url('/authorize') . '?' . http_build_query($params));
    }

    public function handleCallback(): CustomerIdentity
    {
        $this->validateConfiguration();

        $request = Yii::$app->request;
        $error = trim((string) $request->get('error', ''));

        if ($error !== '') {
            throw new CustomerSessionException((string) $request->get('error_description', $error));
        }

        $state = (string) $request->get('state', '');
        $expectedState = (string) Yii::$app->session->get($this->stateSessionKey, '');

        if ($state === '' || $expectedState === '' || !hash_equals($expectedState, $state)) {
            throw new CustomerSessionException('Invalid OIDC state.');
        }

        $code = trim((string) $request->get('code', ''));
        $codeVerifier = (string) Yii::$app->session->get($this->codeVerifierSessionKey, '');

        if ($code === '' || $codeVerifier === '') {
            throw new CustomerSessionException('Missing OIDC authorization code.');
        }

        $tokens = $this->exchangeCode($code, $codeVerifier);
        $claims = $this->decodeAndValidateIdToken((string) ($tokens['id_token'] ?? ''));
        $userinfo = $this->fetchUserInfo((string) ($tokens['access_token'] ?? ''));
        $claims = array_merge($claims, array_filter($userinfo, static fn ($value) => $value !== null && $value !== ''));

        $identity = new CustomerIdentity(
            (string) ($claims['sub'] ?? ''),
            isset($claims['email']) ? (string) $claims['email'] : null,
            isset($claims['name']) ? (string) $claims['name'] : null,
            (bool) ($claims['email_verified'] ?? false)
        );

        if ($identity->authSubject === '') {
            throw new CustomerSessionException('OIDC identity is missing subject.');
        }

        Yii::$app->session->set($this->identitySessionKey, $identity->toArray());
        $this->clearTransientSession();

        return $identity;
    }

    public function logout(string $returnUrl): Response
    {
        Yii::$app->session->remove($this->identitySessionKey);
        $this->clearTransientSession();

        $params = [
            'client_id' => $this->clientId,
            'returnTo' => $returnUrl,
        ];

        return Yii::$app->response->redirect($this->auth0Url('/v2/logout') . '?' . http_build_query($params));
    }

    public function getReturnUrl(string $fallback = '/'): string
    {
        $returnUrl = trim((string) Yii::$app->session->get($this->returnUrlSessionKey, ''));
        Yii::$app->session->remove($this->returnUrlSessionKey);

        return $returnUrl !== '' ? $returnUrl : $fallback;
    }

    private function exchangeCode(string $code, string $codeVerifier): array
    {
        $client = new Client();
        $payload = [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $codeVerifier,
        ];

        if ($this->clientSecret !== '') {
            $payload['client_secret'] = $this->clientSecret;
        }

        $response = $client->request('POST', $this->auth0Url('/oauth/token'), [
            'json' => $payload,
            'headers' => ['Accept' => 'application/json'],
            'http_errors' => false,
        ]);

        $body = Json::decode((string) $response->getBody(), true);

        if ($response->getStatusCode() !== 200 || !is_array($body)) {
            throw new CustomerSessionException('Unable to exchange OIDC authorization code.');
        }

        return $body;
    }

    private function fetchUserInfo(string $accessToken): array
    {
        if ($accessToken === '') {
            return [];
        }

        $client = new Client();
        $response = $client->request('GET', $this->auth0Url('/userinfo'), [
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer ' . $accessToken,
            ],
            'http_errors' => false,
        ]);

        if ($response->getStatusCode() !== 200) {
            return [];
        }

        $body = Json::decode((string) $response->getBody(), true);

        return is_array($body) ? $body : [];
    }

    private function decodeAndValidateIdToken(string $idToken): array
    {
        $parts = explode('.', $idToken);

        if (count($parts) !== 3) {
            throw new CustomerSessionException('Invalid OIDC id token.');
        }

        $claims = Json::decode($this->base64UrlDecode($parts[1]), true);

        if (!is_array($claims)) {
            throw new CustomerSessionException('Invalid OIDC claims.');
        }

        $issuer = rtrim($this->auth0Url('/'), '/') . '/';
        $audience = $claims['aud'] ?? null;
        $expectedNonce = (string) Yii::$app->session->get($this->nonceSessionKey, '');

        if (($claims['iss'] ?? '') !== $issuer) {
            throw new CustomerSessionException('Invalid OIDC issuer.');
        }

        if (is_array($audience) ? !in_array($this->clientId, $audience, true) : $audience !== $this->clientId) {
            throw new CustomerSessionException('Invalid OIDC audience.');
        }

        if (!empty($claims['exp']) && time() >= (int) $claims['exp']) {
            throw new CustomerSessionException('OIDC id token expired.');
        }

        if ($expectedNonce !== '' && !hash_equals($expectedNonce, (string) ($claims['nonce'] ?? ''))) {
            throw new CustomerSessionException('Invalid OIDC nonce.');
        }

        return $claims;
    }

    private function validateConfiguration(): void
    {
        foreach (['domain', 'clientId', 'redirectUri'] as $property) {
            if (trim((string) $this->$property) === '') {
                throw new CustomerSessionException("Customer session configuration '{$property}' is required.");
            }
        }
    }

    private function clearTransientSession(): void
    {
        Yii::$app->session->remove($this->stateSessionKey);
        Yii::$app->session->remove($this->nonceSessionKey);
        Yii::$app->session->remove($this->codeVerifierSessionKey);
    }

    private function auth0Url(string $path): string
    {
        $domain = preg_match('/^https?:\/\//', $this->domain) ? $this->domain : 'https://' . $this->domain;

        return rtrim($domain, '/') . '/' . ltrim($path, '/');
    }

    private function randomUrlSafeString(int $bytes): string
    {
        return $this->base64UrlEncode(random_bytes($bytes));
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): string
    {
        $padding = strlen($value) % 4;

        if ($padding > 0) {
            $value .= str_repeat('=', 4 - $padding);
        }

        return (string) base64_decode(strtr($value, '-_', '+/'), true);
    }
}
