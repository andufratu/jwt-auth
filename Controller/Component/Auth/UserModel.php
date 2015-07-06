<?php
namespace AnduFratu\Jwt;

interface UserModel
{
    public function getRefreshToken(array $user);
}
