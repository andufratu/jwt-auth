<?php
namespace AnduFratu\Jwt;

use \JWT;

\App::uses('BaseAuthenticate', 'Controller/Component/Auth');

class JwtAuthenticate extends \BaseAuthenticate
{

    const KEY = 'secretKey';

    public function __construct(\ComponentCollection $collection, $settings = array())
    {
        $settings = \Hash::merge(
            array(
                'param' => 'token',
            ),
            $settings
        );

        parent::__construct($collection, $settings);
    }

    public function authenticate(\CakeRequest $request, \CakeResponse $response)
    {
        return false;
    }

    public function getUser(\CakeRequest $request)
    {
        $token = $this->_getToken($request);
        if ($token)
        {
            $username = $this->_getUsername($token);
            return $this->_findUser($username);
        }

        return false;
    }

    private function _getToken(\CakeRequest $request)
    {
        return $request->param($this->settings['param']);
    }

    private function _getUsername($token)
    {
        $payload = (array) \JWT::decode($token, self::KEY);
        $user = $this->_findUser($payload['sub']);
    }
}
