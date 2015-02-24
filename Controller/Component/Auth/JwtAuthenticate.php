<?php
namespace AnduFratu\JWT;

App::uses('BaseAuthenticate', 'Controller/Component/Auth');

class JwtAuthenticate extends BaseAuthenticate
{

    public function __construct(ComponentCollection $collection, $settings)
    {
        parent::__construct($collection, $settings);
    }


}
