<?php
namespace AnduFratu\Jwt;

class TokenExpiredException extends \CakeException
{
    public function __construct()
    {
        parent::__construct('Token expired');
    }
}
