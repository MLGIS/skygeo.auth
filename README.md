# skygeo.auth
AI 代码生成
auth2分支中修改为auth2支持的授权模式，同时增加密码获取token模式，测试用例如下：
curl -X POST http://localhost:9000/oauth2/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "Authorization: Basic c2t5Z2VvLWNsaWVudDpzZWNyZXQ=" \
     -d "grant_type=password&username=admin&password=admin123&scope=read"