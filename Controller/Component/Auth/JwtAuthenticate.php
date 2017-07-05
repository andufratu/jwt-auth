<?php
namespace AnduFratu\Jwt;

use Firebase\JWT\JWT;

\App::uses('BaseAuthenticate', 'Controller/Component/Auth');

class JwtAuthenticate extends \BaseAuthenticate
{
    private $defaultSettings = array(
        'param' => 'token',
        'key' => NULL,
        'alg' => 'RS256',
        'auth_type_claim_name' => 'auth',
        'auth_type_claim_value' => 'auth',
    );

    private $errorMessage;

    public function __construct(\ComponentCollection $collection, $settings = array())
    {
        $settings = \Hash::merge(
            $this->defaultSettings,
            $settings
        );

        parent::__construct($collection, $settings);
    }

    public function authenticate(\CakeRequest $request, \CakeResponse $response)
    {
        $token = $this->getToken($request);
        $user = false;
        if ($token)
        {
            try
            {
                $payload = (array) JWT::decode($token, $this->settings['key'], array($this->settings['alg']));
                $username = $payload['sub'];
                $user = $this->_findUser($username);
            }
            catch (\Firebase\JWT\ExpiredException $e)
            {
                $tks = explode('.', $token);
                list($headb64, $bodyb64, $cryptob64) = $tks;
                $payload = JWT::jsonDecode(JWT::urlsafeB64Decode($bodyb64));
                $username = $payload->sub;
                $user = $this->_findUser($username);
            }
            catch (\Exception $e)
            {
                // Treat as non-authenticated
            }
        }
        return $user;
    }

    public function getUser(\CakeRequest $request)
    {
        $token = $this->getToken($request);
        $user = false;
        if ($token)
        {
            try
            {
                $payload = (array) JWT::decode($token, $this->settings['key'], array($this->settings['alg']));
                $username = $payload['sub'];

                $user = $this->_findUser($username);
            }
            catch (\Firebase\JWT\ExpiredException $e)
            {
                $tks = explode('.', $token);
                list($headb64, $bodyb64, $cryptob64) = $tks;
                $payload = JWT::jsonDecode(JWT::urlsafeB64Decode($bodyb64));
                if ($payload->{$this->settings['auth_type_claim_name']} === $this->settings['auth_type_claim_value'])
                {
                    $usernameField = $this->settings['fields']['username'];
                    $userModel = \ClassRegistry::init($this->settings['userModel']);
                    $user = $userModel->find('first', array(
                        'conditions' => array(
                            $usernameField => $payload->sub,
                        )
                    ));
                    throw new \TokenExpiredException($userModel->getRefreshToken($user));
                }
            }
            catch (\Exception $e)
            {
                $this->errorMessage = $e->getMessage();
            }
        }

        return $user;
    }

    public function unauthenticated(\CakeRequest $request, \CakeResponse $response)
    {
        throw new \TokenInvalidException('Token invalid: ' . $this->errorMessage);
        return true;
    }

    private function getToken(\CakeRequest $request)
    {
        $authHeader = $request->header('Authorization');
        if ($authHeader)
        {
            $token = preg_replace('/Bearer (.+)$/', '$1', $authHeader);
        }
        else
        {
            $token = $request->param($this->settings['param']);
        }

        return $token;
    }
}
