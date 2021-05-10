var createError = require("http-errors");
var express = require("express");
var path = require("path");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
const expressJwt = require("express-jwt"); //模块引入
var indexRouter = require("./routes/index");
var usersRouter = require("./routes/users");
const cors = require("cors");
var app = express();
// 引入 jwt token 生成文件
const Jwt = require("./public/javascripts/jwt");
app.use(
  cors({
    origin: [
      "http://127.0.0.1:8080",
      "http://localhost:8080",
      "http://192.168.31.51:8080",
    ],
  })
);
app.use((req, res, next) => {
  // 如果是需要携带token才能访问的路径
  if (req.url.startsWith("/")) {
    // 获取请求头中的token
    let token = req.headers.token;

    // 验证【解析】token
    let result = new Jwt(token).verifyToken();
    // 验证结果处理

    if (result.name == "TokenExpiredError") {
      // 如果返回结果的name属性是TokenExpiredError，则说明token已超时
      res.send({ code: 403, msg: "token超时" });
    } else if (result.name == "JsonWebTokenError") {
      // 如果返回结果是JsonWebTokenError，则说明token不对,并生成新token 返回
      let token = new Jwt().generateToken();
      res.send({ code: 403, msg: "token错误", token: token });
    } else {
      // 如果正确解析了数据对象，将数据对象赋值给data，继续执行
      let token = new Jwt().generateToken();
      res.send({
        code: 200,
        msg: "token正确",
        data: { id: 1, val: "不会吧" },
        token: token,
      });
    }
  }
});
// view engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.use("/", indexRouter);
app.use("/users", usersRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render("error");
});

app.listen(3000, () => {
  console.log('server is running...');
});

module.exports = app;
