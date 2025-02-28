<?php

declare(strict_types=1);

namespace App\Http\Controllers\SSO;

use App\Enums\AuthMethodTypes;
use App\Enums\UserRole;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use WorkOS\UserManagement;
use WorkOS\WorkOS;

class AuthController extends Controller
{
    public function redirectToWorkOS()
    {
        WorkOS::setApiKey(config('workos.api_key'));
        WorkOS::setClientId(config('workos.client_id'));

        $userManagement = new UserManagement;

        $authorizationUrl = $userManagement->getAuthorizationUrl(
            redirectUri: config('workos.redirect_uri'),
            provider: 'authkit',
        );

        return redirect($authorizationUrl);
    }

    public function handleCallback(Request $request)
    {
        WorkOS::setApiKey(config('workos.api_key'));
        WorkOS::setClientId(config('workos.client_id'));
        $userManagement = new UserManagement;

        try {
            $workOSResponse = $userManagement->authenticateWithCode(
                clientId: config('workos.client_id'),
                code: $request->input('code'),
            );

            $authenticationMethod = $workOSResponse->authentication_method;

            //@TODO Currently support only password auth type
            // Need to add support for other auth types
            if ($authenticationMethod !== AuthMethodTypes::PASSWORD->value) {
                return redirect()->route('error.page')->with('error', 'Invalid authentication method.');
            }

            $workOSUser = $workOSResponse->user;
            $user = User::updateOrCreate(
                ['email' => $workOSUser->email],
                [
                    'first_name' => $workOSUser->firstName,
                    'last_name' => $workOSUser->lastName,
                    'role' => UserRole::USER,
                    'workos_user_id' => $workOSUser?->id,
                    'profile_picture_url' => $workOSUser?->profilePictureUrl,
                    'authentication_method' => $authenticationMethod,
                ],
            );

            Auth::login($user);

            return redirect()->route('users.index');
        } catch (\Exception $e) {
            return redirect()->route('login')->with('error', 'Failed to authenticate.');
        }
    }
}
