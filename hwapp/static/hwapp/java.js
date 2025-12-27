var validate = function(e) {
    var t = e.value;
    e.value = (t.indexOf(".") >= 0) ? (t.substr(0, t.indexOf(".")) + t.substr(t.indexOf("."), 1)) : t;
    
}
$('#add_hw_form').submit(function () {
    return false;
   });

$('#non_functional_form').submit(function () {
    return false;
   });
function openNav() {
    var nav = document.getElementById("mySidenav");
    nav.style.width = "250px";
  }
  
  function closeNav() {
    var nav = document.getElementById("mySidenav");
    nav.style.width = "0";
  }
function show_item(id) {
    var show = document.getElementById(id).style.display
    if(show=='block') {
        document.getElementById(id).style.display = 'none'
        console.log(true)
    } else {
        document.getElementById(id).style.display = 'block'
        console.log(show)
    }
}
