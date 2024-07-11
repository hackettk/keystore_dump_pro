# keystore_dump_pro
解决keystore_dump，无法dump HTTPS证书的问题

![image](https://github.com/hackettk/keystore_dump_pro/assets/45909680/c964865e-e759-407a-864a-7bdc26338c8a)


**Frida Command Line**
`frida -Uf com.xxx.xxx -l keystore_dump_pro.js --no-pause`

执行后，https证书 会在手机目录:``/data/user/0/com.xxx.xxx/client_keystore__xxx.p12``
