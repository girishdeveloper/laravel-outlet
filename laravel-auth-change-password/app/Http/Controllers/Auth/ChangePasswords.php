<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Support\Str;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Foundation\Auth\RedirectsUsers;

trait ChangePasswords
{
    use RedirectsUsers;

    /**
     * Display the change password view.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Contracts\View\Factory|\Illuminate\View\View
     */
    public function showChangeForm(Request $request)
    {
        return view('auth.passwords.change');
    }

    /**
     * Change the loggedin user's password.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\JsonResponse
     */
    public function change(Request $request)
    {
        $request->validate($this->rules(), $this->validationErrorMessages());

        $response = "passwords.change";
        //check if the current password is correct.
        if(!(Hash::check($request->get('current_password'), Auth::user()->password))) {
            // The passwords do not match
            $response = ["current_password" => "The current password is wrong."];
        }
        if(strcmp($request->post('current_password'), $request->post('password')) == 0) {
            // The passwords are same
            $response = ["password" => "The new password you provided is same as before."];
        }
        //check if any errors.
        if($response == "passwords.change") {
            $this->changePassword(Auth::user(), $request->post('password'));
        }

        // If the password was successfully change, we will redirect the user back to
        // the application's home authenticated view. If there is an error we can
        // redirect them back to where they came from with their error message.
        return $response == "passwords.change"
                    ? $this->sendChangeResponse($request, $response)
                    : $this->sendChangeFailedResponse($request, $response);
    }

    /**
     * Get the password change validation rules.
     *
     * @return array
     */
    protected function rules()
    {
        return [
            'current_password' => 'required',
            'password' => 'required|string|min:8|confirmed',
        ];
    }

    /**
     * Get the password change validation error messages.
     *
     * @return array
     */
    protected function validationErrorMessages()
    {
        return [];
    }

    /**
     * Get the password change credentials from the request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
     */
    protected function credentials(Request $request)
    {
        return $request->only(
            'current_password', 'password', 'password_confirmation'
        );
    }

    /**
     * Change the loggedin user's password.
     *
     * @param  \Illuminate\Contracts\Auth\CanResetPassword  $user
     * @param  string  $password
     * @return void
     */
    protected function changePassword($user, $password)
    {
        $user->password = Hash::make($password);

        $user->setRememberToken(Str::random(60));

        $user->save();

        event(new PasswordReset($user));

        $this->guard()->login($user);
    }

    /**
     * Get the response for a successful password change.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $response
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\JsonResponse
     */
    protected function sendChangeResponse(Request $request, $response)
    {
        return redirect($this->redirectPath())
                            ->with('status', trans($response));
    }

    /**
     * Get the response for a failed password change.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $response
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\JsonResponse
     */
    protected function sendChangeFailedResponse(Request $request, $response)
    {
        $key = array_keys($response);
        return redirect()->back()
                    ->withInput($request->only($key[0]))
                    ->withErrors([$key[0] => trans($response[$key[0]])]);
    }

    /**
     * Get the guard to be used during password change.
     *
     * @return \Illuminate\Contracts\Auth\StatefulGuard
     */
    protected function guard()
    {
        return Auth::guard();
    }
}
