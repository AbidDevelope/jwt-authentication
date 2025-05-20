<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Exception;
use Carbon\Carbon;

class AuthController extends Controller
{
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
        ], 404);
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
            'message' => "OTP has been sent to. $request->mobile"
        ], 200);
       }
    }

    public function verifyOtp(Request $request)
    {
        try
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

            $token = JWTAuth::fromUser($user); 
            if(!$token)
            {
                return response()->json(['token' => 'An error occured'], 500);
            }

            if($token)
            {
                $user->update(['otp' => null, 'expire_at' => null]);
            } 

            return response()->json([
                'status' => true,
                'message' => 'You Have Successfully login',
                'user'=> [
                    'id' => $user->id,
                    'name' =>   $user->name,
                    'mobile' => $user->mobile
                ],
                'token' => $token,
            ], 200); 
        }
        catch(\JWTException $e)
        {
         return response()->json([
            'status' => false,
            'message' => 'Token generation failed'
         ], 500);
        }
        catch(\Exception $e)
        {
            return response()->json([
                'status' => false,
                'message' => 'An error occured during otp verification.'
            ], 500);
        }
                 
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
        ], 200);
    }

    public function me()
    {
        $user = Auth::guard('api')->user();
        if(!$user)
        {
            return response()->json(['status' => false, 'user' => 'user not found'], 404);
        }
        return response()->json(['status' => true, 'user' => $user], 200);
    }    

    public function update(Request $request, User $user)
    {
       try{
            $user = Auth::guard('api')->user();  
            if(!$user)
            {
                return response()->json(['status' => false, 'message' => 'auhtenticated user not found'], 404);
            }

     
            $validator = Validator::make($request->all(), [
                'name' => 'required|string|max:255',
            ]);

            if($validator->fails())
            {
                return response()->json([
                    'status' => false,
                    'error' => $validator->errors()
                ], 422);
            }
           
            $user->name = $request->input('name');
            $user->save();

            return response()->json([
                'status' => true,
                'message' => 'User Updated Successfully',
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'updated' => $user->updated_at
                ]
            ], 200);

       }
       catch(\Exception $e)
       {
        return response()->json([
            'status' => false,
            'message' => 'An error occurred while updating the user.'
        ], 500);
       }
       catch(\JWTExecption $e)
       {
        return response()->json([
            'status' => false,
            'message' => 'invalid or expired token'
        ], 401);
       }
    }

    public function logout(Request $request)
    {
        try {
            $user = Auth::guard('api')->user();
            if(!$user)
            {
                return response()->json(['status'=> false, 'message' => 'No authentcated user found'], 404);
            }

            JWTAuth::parseToken()->invalidate(true);
            Auth::guard('api')->logout();

            return response()->json([
                'status' => true,
                'message' => 'Succcessfully logout',
                'user' => $user
            ], 200);
        }catch(\Exception $e) 
        {
            return $e->getMessage();
        }catch(\JWTException $e)
        {
          return response()->json([
            'status' => false,
            'message' => 'Failed to invalidate token.'
          ], 400);
        }
    }
}
