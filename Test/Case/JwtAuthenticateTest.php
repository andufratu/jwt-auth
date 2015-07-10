<?php
namespace AnduFratu\Jwt;

use \JWT;

\App::uses('Controller', 'Controller');

class JwtAuthenticateTest extends \CakeTestCase
{
    const ALGORITHM = 'HS256';
    const TYPE_CLAIM_NAME = 'type';
    const TYPE_CLAIM_AUTH_VALUE = 'auth';
    const TYPE_CLAIM_REFRESH_VALUE = 'refresh';
    const KEY = 'key';
    const OTHER_KEY = 'otherkey';
    const OTHER_USER_ID = 1;
    const PARAM_NAME = 'token';
    const USER_EMAIL = 'test@user.com';
    const USER_ID = 1;
    const USER_NAME = 'Test User';

    private $controller;

    private $keys = array(
        self::USER_ID => self::KEY,
        self::OTHER_USER_ID => self::OTHER_KEY,
    );

    private $jwt;

    private $request;

    private $returnedUser;

    private $userModel;

    public function setUp()
    {
        parent::setUp();

        \Configure::write('App', array(
            'dir' => APP_DIR,
            'webroot' => WEBROOT_DIR,
            'base' => false,
            'baseUrl' => '/cake/index.php'
        ));

        $this->request = $this->getMock('\CakeRequest');
        $this->controller = new TestController($this->request, $this->getMock('CakeResponse'));
        $collection = new \ComponentCollection();
        $collection->init($this->controller);
        $this->jwt = new JwtAuthenticate($collection, array(
            'fields' => array(
                'username' => 'email',
            ),
            'param' => self::PARAM_NAME,
            'key' => $this->keys,
            'alg' => self::ALGORITHM,
            'userModel' => 'AnduFratu\\Jwt\\User',
            'auth_type_claim_name' => self::TYPE_CLAIM_NAME,
            'auth_type_claim_value' => self::TYPE_CLAIM_AUTH_VALUE,
        ));
    }

    public function testReturnsCorrectUserForValidTokenFromParams()
    {
        $this->givenARequestWithAValidTokenInParams();
        $this->givenAUser();

        $this->whenGettingUser();

        $this->verifyCorrectUserIsReturned();
    }

    public function testReturnsCorrectUserForValidTokenFromHeader()
    {
        $this->givenARequestWithAValidTokenInHeader();
        $this->givenAUser();

        $this->whenGettingUser();

        $this->verifyCorrectUserIsReturned();
    }

    public function testExpiredTokenThrowsTokenExpiredException()
    {
        $this->setExpectedException('TokenExpiredException');
        $this->givenARequestWithAnExpiredToken();

        $this->whenGettingUser();
    }

    public function testExpiredTokenReturnsFalseIfNotTheRightType()
    {
        $this->givenARequestWithAnExpiredToken(self::TYPE_CLAIM_REFRESH_VALUE);

        $this->whenGettingUser();

        $this->verifyAuthorizationDenied();
    }

    public function testUnexpectedErrorDeniesAuthorization()
    {
        $this->givenARequestWithAnInvalidToken();

        $this->whenGettingUser();

        $this->verifyAuthorizationDenied();
    }

    public function testAuthenticateReturnsFalse()
    {
        $this->assertFalse($this->jwt->authenticate($this->request, $this->getMock('\CakeResponse')));
    }

    public function testUnauthenticatedThrowsTokenInvalidException()
    {
        $this->setExpectedException('TokenInvalidException');
        $this->jwt->unauthenticated($this->request, $this->getMock('\CakeResponse'));
    }

    private function givenAUser()
    {
        $this->user = \ClassRegistry::init('AnduFratu\Jwt\User');
        $this->user->addRecord(
            array(
                'userId' => self::USER_ID,
                'name' => self::USER_NAME,
                'email' => self::USER_EMAIL,
            )
        );
    }

    private function givenARequestWithAnExpiredToken($authClaimValue = self::TYPE_CLAIM_AUTH_VALUE)
    {
        $payload = array(
            'sub' => self::USER_EMAIL,
            'iat' => time() - 3601,
            'exp' => time() - 1,
            self::TYPE_CLAIM_NAME => $authClaimValue,
        );
        $token = \JWT::encode($payload, $this->keys[self::USER_ID], self::ALGORITHM, self::USER_ID);
        $this->setToken($token);
    }

    private function givenARequestWithAnInvalidToken()
    {
        $token = 'NOTAVALIDTOKEN';
        $this->setToken($token);
    }

    private function givenARequestWithAValidTokenInParams()
    {
        $payload = $this->getValidTokenPayload();
        $token = \JWT::encode($payload, $this->keys[self::USER_ID], self::ALGORITHM, self::USER_ID);
        $this->setToken($token, false);
    }

    private function givenARequestWithAValidTokenInHeader()
    {
        $payload = $this->getValidTokenPayload();
        $token = \JWT::encode($payload, $this->keys[self::USER_ID], self::ALGORITHM, self::USER_ID);
        $this->setToken($token);
    }

    private function getValidTokenPayload()
    {
        return array(
            'sub' => self::USER_EMAIL,
            'iat' => time(),
            'exp' => time() + 3600,
            self::TYPE_CLAIM_NAME => self::TYPE_CLAIM_AUTH_VALUE,
        );
    }

    private function setToken($token, $inHeader = true)
    {
        if ($inHeader)
        {
            $this->request->staticExpects($this->once())
                ->method('header')
                ->with('Authorization')
                ->will($this->returnValue($token));
        }
        else
        {
            $this->request->expects($this->any())
                ->method('param')
                ->with(self::PARAM_NAME)
                ->will($this->returnValue($token));
        }
    }

    private function whenGettingUser()
    {
        $this->returnedUser = $this->jwt->getUser($this->request);
    }

    private function verifyCorrectUserIsReturned()
    {
        $this->assertEquals(self::USER_ID, $this->returnedUser['userId']);
    }

    private function verifyAuthorizationDenied()
    {
        $this->assertEquals(false, $this->returnedUser);
    }
}

class TestController extends \Controller
{

    public $uses = array('AnduFratu\\Jwt\\User');

}

class User extends \CakeTestModel implements \AnduFratu\Jwt\UserModel
{
    public $useTable = false;

    private $records = array();

    protected $_schema = array(
        'userId' => array(
            'type' => 'string',
        ),
        'name' => array(
            'type' => 'string',
        ),
        'email' => array(
            'type' => 'string',
        ),
    );

    public function addRecord($record)
    {
        $this->records[] = array(
            __CLASS__ => $record
        );
    }

    public function find($type = 'first', $query = array())
    {
        $this->conditions = isset($query['conditions']) ? $query['conditions'] : array();
        $results = array_filter($this->records, array($this, 'filter'));

        if (count($results) > 0)
        {
            if ($type == 'first')
            {
                return $results[0];
            }
            else
            {
                return $results;
            }
        }
        else
        {
            return array();
        }
    }

    public function filter($record)
    {
        $filterOut = false;
        foreach ($this->conditions as $key => $value)
        {
            $key = preg_replace('/[^.]+\.(.+)$/', '$1', $key);
            if (!isset($record[$key]) || $record[$key] != $value)
            {
                $filterOut = true;
                break;
            }
        }

        return $filterOut;
    }

    public function getRefreshToken(array $user) {
        return 'REFRESH_TOKEN';
    }
}
