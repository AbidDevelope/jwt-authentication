<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Exception;
use Carbon\Carbon;

class AuthController extends Controller
{
    // public function __constuct()
    // {
    //     $this->middleware('auth:api', ['except' => ['login', 'register']]);
    // } 

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'mobile' => 'required|integer|digits:10|unique:users',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6|confirmed',
            'password_confirmation' => 'required|min:6'
        ]); 

        if($validator->fails())
        {
            return response()->json($validator->errors(), 422);
        }

        $user = User::create([
            'name' => $request->name,
            'mobile' => $request->mobile,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]); 

        if($user)
        {
            $token = Auth::guard('api')->login($user);

            return response()->json([
                'status' => true,
                'message' => 'User created successfully',
                'autorizatoin' => [
                    'token' => $token,
                    'type' => 'bearer'
                ]
            ], 200);
        }
    }

    public function sendOtp(Request $request)
    {
       $validator = Validator::make($request->all(), [
        'mobile' => 'required|max:10|min:10',
        ]);

       if($validator->fails())
       {
        return response()->json($validator->errors(), 422);
       }

       $users = User::where(['mobile' => $request->mobile])->first();
       if(!$users)
       {
        return response()->json([
            'status' => false,
            'message' => 'user not found! Please first register'
        ]);
       }

       $otp = rand(1000, 9999);
       
       $otpSend = $users->update([
        'otp' => $otp,
        'expire_at' => Carbon::now()->addMinutes(5),
       ]);

       if($otpSend)
       {
        return response()->json([
            'status' => true,
            'message' => "OTP sent successfully to number. $request->mobile"
        ]);
       }
    }

    public function verifyOtp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'mobile' => 'required|digits:10',
            'otp' => 'required|digits:4'
        ]); 

        if($validator->fails())
        {
            return response()->json($validator->errors(), 422);
        }

        $user = User::where('mobile', $request->mobile)->where('otp', $request->otp)
                      ->where('expire_at', '>=', now())->first();
        if(!$user)
        {
            return response()->json(['error' => 'Invalid or expire otp'], 401);
        }   

        $token = Auth::guard('api')->login($user); 
        if(!$token)
        {
            return response()->json(['token' => 'token generation failed'], 500);
        }

        if($token)
        {
            $user->update(['otp' => null]);
        } 

        return response()->json([
            'status' => true,
            'message' => 'You Have Successfully login',
            'users'=> [
                'id' => $user->id,
               'name' => $user->name,
               'mobile' => $user->mobile
            ],
            'token' => $token,
        ]);              
    }       

    public function profile()
    {
        $user = Auth::guard('api')->user();
        if(!$user)
        {
            return response()->json([
                'status' => false,
                'user' => 'user not found'
            ]);
        }

        return response()->json([
            'status' => true,
            'user' => $user
        ]);
    }

    public function logout(Request $request)
    {
        
        try {
            $token = JWTAuth::invalidate(JWTAuth::parseToken());
            if(!$token)
            {
                return response()->json([
                    'error' => 'token error invaladate'
                ]);
            }

            return response()->json([
                'status' => true,
                'message' => 'Succcessfully logout'
            ]);
        }catch(Exception $e) {
            return $e->getMessage();
        }
    }
}
