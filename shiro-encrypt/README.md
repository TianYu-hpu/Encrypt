#Shiro-encrypt
　　在web端登陆的时候客户端(Android/iOS/网页),在进行登陆操作的时候首先从服务器那边根据session获取一个加密用的公钥，服务器端根据每个用户生成不同的密钥对，并存储进session中，客户端在进行密码登陆的时候，从输入框中获取用户的明文密码之后将密码使用服务器端传过来的公钥进行加密，然后传给服务器端，服务器端拿着密钥进行解密，获取密码明文，然后获得密码明文之后，根据登陆的用户名，从数据库中查找到用户信息，拿到该用户的salt,以及数据库中加密后的密码，将解密后的密码明文通过相同的加密算法进行加密，得到密码的密文，然后和数据库进行比较，如果一致，则说明用户名密码正确，否则错误。

　　在对用户明文密码进行加密存储的时候，使用Shiro提供的Api，获取用户的明文密码，然后随机生成一个私盐，这个私盐保证在每次生成的时候都不一样，然后将两者混合后使用SHA-512这种算法进行Hash,设置迭代次数为256或者512，将这种方式加密后的密文存到数据库中，并将生成的salt也存到数据库中，方便下次用户登录的时候比对密码