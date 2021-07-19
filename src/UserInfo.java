public class UserInfo {

    String username;
    String password;

    public UserInfo(String username, String password){
        this.username = username;
        this.password = password;
    }

    public void changePass(String newPass){
       this.password  = newPass;
    }

    public String getUser(){
        return username;
    }

    public String getPass(){
        return password;
    }

}
