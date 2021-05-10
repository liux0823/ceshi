// 引入所需模块
const jwt = require("jsonwebtoken");
const qs = require("qs");
const path = require("path");
const fs = require("fs");
//构建Jwt类
class Jwt {
  // 获取数据库中返回的数据对象 || 请求头中传来的token
  constructor(data) {
    this.data = data;
  }
  // 生成token
  generateToken() {
    // 拿到数据库中返回的数据对象
    let data = this.data;
    // 拿到生成token时的时间（距离计算机元年的秒数）
    let created = Math.floor(Date.now() / 1000);
    // fs模块，同步读取，拿到openssl生成的私钥
    let cert = fs.readFileSync(path.resolve(__dirname, "./jwt.pem"));
    // 通过jwt生成token
    let token = jwt.sign(
      {
        // 数据库中返回的数据对象
        data,
        //过期时间
        exp: created + 60 * 60,
      },
      cert,
      { algorithm: "RS256" }
    );
    // 将生成的token return出去
    return token;
  }
  // 校验token
  verifyToken() {
    // 请求头中的token
    let token = this.data;
    // fs模块，同步读取，拿到openssl生成的公钥
    let cert = fs.readFileSync(path.resolve(__dirname, "./jwt_pub.pem"));
    // 存储token的校验【解析】结果
    let res;
    //开始对token进行解析
    try {
      // 如果token不是undefined
      if (token !== "undefined") {
        //获取校验【解析】token所获得的数据对象
        let result = jwt.verify(token, cert, { algorithm: "RS256" }) || {};
        // 存储token的校验【解析】结果
        res = result.data || {};
      }
    } catch (e) {
      res = e;
    }
    // 返回校验结果
    return res;
  }
}
//导出Jwt对象
module.exports = Jwt;
