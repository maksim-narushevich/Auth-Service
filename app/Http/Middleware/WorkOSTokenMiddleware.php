<?php

namespace App\Http\Middleware;

use App\Models\User;
use Closure;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use WorkOS\UserManagement;
use WorkOS\WorkOS;

class WorkOSTokenMiddleware
{
    /**
     * @throws AuthenticationException
     * @throws GuzzleException
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken();
        if (! $token) {
            throw new AuthenticationException(message: 'Unauthorized - Token missing');
        }

        try {
            session()->flush();
            WorkOS::setApiKey(config('workos.api_key'));
            WorkOS::setClientId(config('workos.client_id'));
            $userManagement = new UserManagement;

            $client = new Client;
            $jwksUrl = $userManagement->getJwksUrl(config('workos.client_id'));
            $response = $client->request('GET', $jwksUrl);
            $jwksJSON = $response->getBody()->getContents();
            $jwks = json_decode($jwksJSON, true);
            $session = JWT::decode($token, JWK::parseKeySet($jwks));

            dump($jwks);
            dump($session);

            if (! $session?->sub) {
                throw new AuthenticationException(message: 'Unauthorized - Invalid token');
            }

            $user = User::where('workos_user_id', $session->sub)->first();

            if (! $user) {
                throw new AuthenticationException(message: 'Unauthorized - User not found');
            }

            Auth::login($user);

            return $next($request);
        } catch (\Exception $e) {
            throw new AuthenticationException(message: $e->getMessage());
        }
    }
}
