<?php
namespace AnduFratu\Jwt;

\App::uses('BaseAuthenticate', 'Controller/Component/Auth');

class JwtAuthenticate extends \BaseAuthenticate
{
    private $defaultSettings = array(
        'param' => 'token',
        'key' => 'EMPTY_KEY',
    );

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
        return false;
    }

    public function getUser(\CakeRequest $request)
    {
        $token = $this->getToken($request);
        $user = false;
        if ($token)
        {
            try
            {
                $payload = (array) \JWT::decode($token, $this->settings['key']);
                $username = $this->_findUser($payload['sub']);

                $user = $this->_findUser($username);
            }
            catch (\UnexpectedValueException $e)
            {
                $user = false;
            }
        }

        return $user;
    }

    public function unauthenticated(\CakeRequest $request, \CakeResponse $response)
    {
        throw new \ForbiddenException();
        return true;
    }

    private function getToken(\CakeRequest $request)
    {
        $headers = apache_request_headers();
        if (isset($headers['Authorization']))
        {
            $authHeader = $headers['Authorization'];
            $token = preg_replace('/Bearer (.+)$/', '$1', $authHeader);
        }
        else
        {
            $token = $request->param($this->settings['param']);
        }

        return $token;
    }
}
