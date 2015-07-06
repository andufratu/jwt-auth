<?php
namespace AnduFratu\Jwt;

\App::uses('BaseAuthenticate', 'Controller/Component/Auth');
// TODO: Figure out a different way to include this
include 'TokenExpiredException.php';

class JwtAuthenticate extends \BaseAuthenticate
{
    private $defaultSettings = array(
        'param' => 'token',
        'key' => NULL,
        'alg' => 'RS256',
        'auth_type_claim_name' => 'auth',
        'auth_type_claim_value' => 'auth',
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
                $payload = (array) \JWT::decode($token, $this->settings['key'], array($this->settings['alg']));
                $username = $payload['sub'];

                $user = $this->_findUser($username);
            }
            catch (\ExpiredException $e)
            {
                $tks = explode('.', $token);
                list($headb64, $bodyb64, $cryptob64) = $tks;
                $payload = \JWT::jsonDecode(\JWT::urlsafeB64Decode($bodyb64));
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
                else
                {
                    throw new ForbiddenException('Token invalid');
                }
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
