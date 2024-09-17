<?php

declare(strict_types=1);

namespace Tests\Integration\Auth;

use App\Enums\ResponseStatus;
use Illuminate\Testing\Fluent\AssertableJson;
use tests\Integration\BaseWebTestCase;


describe('POST /auth/me', function () {
    it('rejects auth user data for unauthenticated', function () {
        $this->postJson(getUrl(BaseWebTestCase::USER_INFO_ROUTE_NAME))
            ->assertStatus(ResponseStatus::UNAUTHORIZED->value)
            ->assertJson(
                [
                    'status'  => ResponseStatus::UNAUTHORIZED->value,
                    'message' => 'Unauthenticated.',
                ]
            );
    });

    it('gets auth user data for authenticated', function () {
        $response = $this->postJson(
            getUrl(BaseWebTestCase::LOGIN_ROUTE_NAME),
            ['email' => $this->user->email, 'password' => $this->mockPass]
        )->decodeResponseJson();

        $this->postJson(
            getUrl(BaseWebTestCase::USER_INFO_ROUTE_NAME),
            headers: ['Authorization' => sprintf('Bearer %s', $response['access_token'])]
        )
            ->assertOk()
            ->assertJson(fn(AssertableJson $json) => $json->hasAll(['user', 'payload']))
            ->assertJsonPath('user.uuid', $this->user->uuid)
            ->assertJsonPath('user.email', $this->user->email)
            ->assertJsonPath('payload.userUuid', $this->user->uuid);
    });
})->group('auth');

