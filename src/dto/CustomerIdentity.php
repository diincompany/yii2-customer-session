<?php

namespace diincompany\customersession\dto;

final class CustomerIdentity
{
    public string $authSubject;
    public ?string $email;
    public ?string $name;
    public bool $emailVerified;

    public function __construct(
        string $authSubject,
        ?string $email = null,
        ?string $name = null,
        bool $emailVerified = false
    ) {
        $this->authSubject = $authSubject;
        $this->email = $email;
        $this->name = $name;
        $this->emailVerified = $emailVerified;
    }

    public static function fromArray(array $data): self
    {
        return new self(
            (string) ($data['authSubject'] ?? $data['sub'] ?? ''),
            isset($data['email']) ? (string) $data['email'] : null,
            isset($data['name']) ? (string) $data['name'] : null,
            (bool) ($data['emailVerified'] ?? $data['email_verified'] ?? false)
        );
    }

    public function toArray(): array
    {
        return [
            'authSubject' => $this->authSubject,
            'email' => $this->email,
            'name' => $this->name,
            'emailVerified' => $this->emailVerified,
        ];
    }
}
