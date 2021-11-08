module com.example.chattingapp {
    requires javafx.controls;
    requires javafx.fxml;


    opens com.example.chattingapp to javafx.fxml;
    exports com.example.chattingapp;
}