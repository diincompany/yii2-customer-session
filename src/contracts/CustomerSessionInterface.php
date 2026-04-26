<?php

namespace diincompany\customersession\contracts;

use diincompany\customersession\dto\CustomerIdentity;
use yii\web\Response;

interface CustomerSessionInterface
{
    public function isGuest(): bool;

    public function getIdentity(): ?CustomerIdentity;

    public function login(string $returnUrl): Response;

    public function handleCallback(): CustomerIdentity;

    public function logout(string $returnUrl): Response;
}
