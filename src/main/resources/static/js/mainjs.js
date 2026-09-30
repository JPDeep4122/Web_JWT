$(document).ready(function() {
    // Hiển thị thông tin người dùng đăng nhập thành công
    if ($('#profile').length > 0) {
        $.ajax({
            type: 'GET',
            url: '/users/me',
            dataType: 'json',
            contentType: "application/json; charset=utf-8",
            beforeSend: function(xhr) {
                if (localStorage.token) {
                    xhr.setRequestHeader('Authorization', 'Bearer ' + localStorage.token);
                }
            },
            success: function(data) {
                var json = JSON.stringify(data, null, 4);
                // $('#profile').html(json);
                $('#profile').html(data.fullName);
                var imageSrc = data.images;
                if (!imageSrc) {
                    imageSrc = '/images/u1.jpg';
                } else if (!imageSrc.startsWith('http') && !imageSrc.startsWith('/')) {
                    imageSrc = '/images/' + imageSrc;
                }
                document.getElementById("images").src = imageSrc;
                // console.log("SUCCESS : ", data);
                // alert('Hello ' + data.email + '! You have successfully accessed to /api/profile.');
            },
            error: function(e) {
                var json = e.responseText;
                // $('#feedback').html(json);
                // console.log("ERROR : ", e);
                alert("Sorry, you are not logged in.");
            }
        });
    }
});

// Hàm đăng xuất
$(document).on('click', '#logout', function() {
    localStorage.clear();
    window.location.href = "/login";
});

// Hàm login
$(document).on('click', '#login', function() {
    var email = document.getElementById('email').value;
    var password = document.getElementById('password').value;
    var basicInfo = JSON.stringify({
        email: email,
        password: password
    });

    $.ajax({
        type: "POST",
        url: "/auth/login",
        dataType: 'json',
        contentType: "application/json; charset=utf-8",
        data: basicInfo,
        success: function(data) {
            localStorage.token = data.token;
            // alert('Got a token from the server! Token: ' + data.token);
            window.location.href = "/user/profile";
        },
        error: function() {
            alert("Login Failed");
        }
    });
});
