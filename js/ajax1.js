
function ajax1(){
		$.ajax({
		  type: 'GET',
		  url: "http://localhost:9000",
		   //crossDomain: true,
			//dataType: 'jsonp',
		  success: function(data) {
			alert(data);
			/*
			alert(obj);
			$("#response").html($(data).find("#response").html());
			//$('#mar1').find("font").html(obj);
			console.log(obj);
			*/
		  }
		});
	
	
}


