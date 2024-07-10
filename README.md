# 1.背景

> 注意，出于业内规范，你应该首先考虑对接硬件加密机（秘钥安全）。

发现网上关于加解密、数字信封这块相关的资料比较少，博客里面断断续续的会有人讨论，特此新建仓库。

- 给需要用到的人一份demo代码
- 整理自己这一块的知识点

![image-20240710022655167](https://markdown-1258124344.cos.ap-guangzhou.myqcloud.com/images/202407100226341.png)





# 2.基本结构

项目呢是为了精简，所以在刻意避免使用各种花里胡哨的代码，你结合自己的实际情况修改即可。

例如：

- 对象是否能复用
- 部分变量是否能提取成常量
- ...

嗯，我写这段话，就是希望你不要直接抄我的代码，这只是个demo项目。



# 3.功能点（已完成）

| 序号 | 类型 | 分类                         | 描述                                          | 文档                                                      | 代码                                                         | 测试类                                                       |
| ---- | ---- | ---------------------------- | --------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | SM2  | CFCA-SM2双证书申请及下载规范 | 双证响应文件解析（解密xx_SM2_PrivateKey.key） | [docs/SM2-双证书请求文件.md](docs/SM2-双证书请求文件.md)) | [src/main/java/cn/yang37/sm2/DoubleCsrResultUtils.java](src/main/java/cn/yang37/sm2/DoubleCsrResultUtils.java) | [src/test/java/cn/yang37/sm2/DoubleCsrResultUtilsTest.java](src/test/java/cn/yang37/sm2/DoubleCsrResultUtilsTest.java) |
| 2    | SM2  | 签名                         | 裸签名(raw)与der签名转换                      | [docs/SM2-双证书请求文件.md](docs/SM2-双证书请求文件.md)  | [src/main/java/cn/yang37/sm2/SM2SignRaw2DerUtils.java](src/main/java/cn/yang37/sm2/SM2SignRaw2DerUtils.java) | [src/test/java/cn/yang37/sm2/SM2SignRaw2DerUtilsTest.java](src/test/java/cn/yang37/sm2/SM2SignRaw2DerUtilsTest.java) |
|      |      |                              |                                               |                                                           |                                                              |                                                              |
|      |      |                              |                                               |                                                           |                                                              |                                                              |
|      |      |                              |                                               |                                                           |                                                              |                                                              |



# 4.待实现

- SM2-双证书申请及下载规范，双证请求文件构建。
- SM2-数字信封
- ...

