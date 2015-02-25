<?php
namespace AnduFratu\Jwt;

use \JWT;

\App::uses('Controller', 'Controller');

class JwtAuthenticateTest extends \CakeTestCase
{
    const PARAM_NAME = 'token';
    const USER_ID = 1;
    const USER_NAME = 'Test User';
    const USER_EMAIL = 'test@user.com';

    private $controller;
    private $jwt;
    private $request;
    private $userModel;
    private $returnedUser;

    public function setUp()
    {
        parent::setUp();

        \Configure::write('App', array(
            'dir' => APP_DIR,
            'webroot' => WEBROOT_DIR,
            'base' => false,
            'baseUrl' => '/cake/index.php'
        ));

        $this->request = new \CakeRequest(null, false);
        $this->controller = new TestController($this->request, $this->getMock('CakeResponse'));
        $collection = new \ComponentCollection();
        $collection->init($this->controller);
        $this->jwt = new JwtAuthenticate($collection, array(
            'fields' => array(
                'username' => 'email',
            ),
            'param' => self::PARAM_NAME,
            'userModel' => 'AnduFratu\\Jwt\\User',
        ));
    }

    public function testReturnsCorrectUserForValidToken()
    {
        $this->givenARequestWithAValidToken();
        $this->givenAUser();

        $this->whenGettingUser();

        $this->verifyCorrectUserIsReturned();
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

    private function givenARequestWithAValidToken()
    {
        $payload = array(
            'iss' => 'JWT Issuer',
            'sub' => self::USER_EMAIL,
            'iat' => time(),
            'exp' => time() + 3600,
        );
        $token = \JWT::encode($payload, JwtAuthenticate::KEY);
        $this->request->addParams(
            array(
                self::PARAM_NAME => $token,
            )
        );
    }

    private function whenGettingUser()
    {
        $this->returnedUser = $this->jwt->getUser($this->request);
    }

    private function verifyCorrectUserIsReturned()
    {
        $this->assertEquals(self::USER_ID, $this->returnedUser['userId']);
    }
}

class TestController extends \Controller
{

    public $uses = array('AnduFratu\\Jwt\\User');

}

class User extends \CakeTestModel
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
}
