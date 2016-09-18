#基于opensaml 和 spring security的单点登录demo
## 1. 在sso-demo根目录运行: mvn clean package
## 2. 把idp-demo/target目录下的idp-demo-1.0-SNAPSHOT.war重名为idp，放到tomcat-idp里面，启动tomcat。
 ### tomcat-idp：端口8080
## 3. 把sp-demo/target目录下的sp-demo-1.0-SNAPSHOT.war重名为sp，放到tomcat-sp/webapps/ROOT下面，启动tomcat
 ### tomcat-sp：端口9090
## 4. 把sp-demo/target目录下的sp1-demo-1.0-SNAPSHOT.war重名为sp1，放到tomcat-sp1/webapps/ROOT下面，启动tomcat
 ### tomcat-sp1：端口9091
## 5. 在浏览器中打开http://localhost:9090
