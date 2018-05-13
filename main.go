package main

import (
	"html/template"
	"log"
	"net/http"
	
	"database/sql"
    "fmt"
    "time"
    _ "github.com/mattn/go-sqlite3"
	
	"bytes"
    "crypto/cipher"
    "crypto/aes"
    "encoding/base64"
	
	"math/rand" 
	"crypto/sha1"
	"strings"
	"math/big"
	"strconv"
)

var tpl *template.Template
var db_location = "./sqlite/end_to_end.db"


type pageData struct {
	Title     string
	FirstName string
}
var inorout	 = false
func init() {
	tpl = template.Must(template.ParseGlob("*.gohtml"))
}

func main() {
	//inorout = false
	http.HandleFunc("/", idx)
	http.HandleFunc("/Register.gohtml", Register)
	http.HandleFunc("/process", processor)
	http.HandleFunc("/out.gohtml", out)

	http.HandleFunc("/Registration.gohtml", Registration)
	http.HandleFunc("/CreatServer.gohtml", CreatServer)
	http.HandleFunc("/Check_My_Account.gohtml", Check_My_Account)
	// Load css
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))
	// Load js
	http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("js"))))
	// Load vendor
	http.Handle("/vendor/", http.StripPrefix("/vendor/", http.FileServer(http.Dir("vendor"))))
	// Load img
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("img"))))
	
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe(":8080", nil)
	
	
}

func function_sha1(text string) string{
	h := sha1.New()
	h.Write([]byte(text))
	hashed := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return hashed
}

func selectrandomnumber(C_id string) int{
	// query
	db, err := sql.Open("sqlite3", db_location)
    checkErr(err)
    rows, err := db.Query("SELECT * FROM smart_card WHERE User_id = '" + C_id + "'")
    checkErr(err)
    var Random_r int
       
    for rows.Next() {
        err = rows.Scan(&Random_r)
        checkErr(err)
        fmt.Println(Random_r)
    }
	return Random_r
}

func selectAim(C_id string) int{
	// query
	db, err := sql.Open("sqlite3", db_location)
    checkErr(err)
    rows, err := db.Query("SELECT * FROM smart_card WHERE User_id = '" + C_id + "'")
    checkErr(err)
    var Aim int

    for rows.Next() {
        err = rows.Scan(&Aim)
        checkErr(err)
        fmt.Println(Aim)
    }
	return Aim
}

func array_search(ind string,ary []string) int {
	for i := range ary {
		if ary[i] == ind {
			// Found!
			return i
		}
	}
	return 0 //
}

func convBase(numberInput string, fromBaseInput string, toBaseInput string) string {
	if fromBaseInput == toBaseInput {
        return numberInput
    }
	fromBase := strings.Split(fromBaseInput, "")
	toBase := strings.Split(toBaseInput, "")
    number := strings.Split(numberInput, "")
	fromLen := len(fromBaseInput)
    toLen := len(toBaseInput)
    numberLen := len(numberInput)
	
	base10 := ""
	//temp_big := big.NewInt(1)
	c := big.NewInt(1)
	a := big.NewInt(1)
	
	
	//tfactorial := big.NewInt(0)

	retval := ""
	if toBaseInput == "0123456789" {
		retval_big := big.NewInt(0)
		
		for i := 1; i < numberLen; i++ {
			b := array_search(number[i-1], fromBase)//
			
			//int --> int64 --> bigint
			b_64 := int64(b)
			b_big := big.NewInt(b_64)
			fromLen_64 := int64(fromLen)
			fromLen_big := big.NewInt(fromLen_64)
			numberLen_64 := int64(numberLen-i)
			numberLen_big := big.NewInt(numberLen_64)
			//EXP
			c := c.Exp(fromLen_big, numberLen_big, nil)//
			//MUL
			a := a.Mul(b_big ,c)//
			retval_big = retval_big.Add(retval_big, a)//
		}
		return retval_big.String()
	}
	if fromBaseInput != "0123456789"{
        base10 = convBase(numberInput, fromBaseInput, "0123456789")
    }else{
        base10 = numberInput
    }
	//base10(string) to base10_int(int)  
    base10_int := new(big.Int)
    base10_int, err := base10_int.SetString(base10, 10)
    if !err {
        fmt.Println("Error")
    }

    biglen := big.NewInt(int64(len(toBaseInput)))

    if base10_int.Cmp(biglen) == -1 {
        fmt.Println("biglen",biglen)
        fmt.Println("base10_int",base10_int)
        return toBase[base10_int.Int64()]
    }
	//base10(string) to base10_big(bigint) 
	base10_big := new(big.Int)
	base10_big,ok := base10_big.SetString(base10, 10)
    if !ok {
        fmt.Println("SetString: error")
    }
	ok = true
	//
	//toLen(int) to toLen_64(int64) to toLen_big(bigint)
	toLen_64 := int64(toLen)
	toLen_big := big.NewInt(toLen_64)
	//
	for base10 != "0" {
		temp_big := big.NewInt(0)
		temp_big = temp_big.Mod(base10_big, toLen_big)
		//temp_big(bigint) to temp_string(string) to temp_int(int)
		temp_string := temp_big.String()
		temp_int,err := strconv.Atoi(temp_string)
		if err != nil {
			panic(err)
		}
		//
		retval = toBase[temp_int] + retval
		//
		toLen_64 = int64(toLen)
		toLen_big = big.NewInt(toLen_64)
		base10_big,ok := base10_big.SetString(base10, 10)
		if !ok {
			fmt.Println("SetString: error")
		}
		base10_big = base10_big.Div(base10_big, toLen_big)
		//
		base10 = base10_big.String()
    }
    return retval
}

func compute_xor(text string, key string) string{
    fmt.Println("text",text)
    str_combind := ""
    for i:=1; i<=len(text); i++ {
        //text[i] = intval(text[i])^intval(key[i])
        text_int,err := strconv.Atoi(text[i-1:i])
        if err != nil {
            panic(err)
        }

        key_int,err := strconv.Atoi(key[i-1:i])
        if err != nil {
            panic(err)
        }


        tempp_str := strconv.Itoa(text_int^key_int)
        str_combind += tempp_str
    }

    return str_combind
}

func processor(w http.ResponseWriter, r *http.Request) {
	
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	
	//fname := r.FormValue("firster")
	C_action := r.FormValue("C_T")
	C_id := r.FormValue("C_id")
	C_password := r.FormValue("C_password")
	var C_state string
    var C_gow string
	
	//var key string
	//key = "0123456789abcdef"
	//var C_id_en string
	//C_id_en = AES_EN(key, C_id)
	//var C_password_en string
	//C_password_en = AES_EN(key, C_password)
	
	
	//C_action
	fmt.Println(C_action)
	if(C_action == "Register"){
		//點註冊時
		
		//random number r    1 ~ 2147483645
        rand.Seed(time.Now().UnixNano())
		randomnumber_r := rand.Intn(2147483644) + 1

        //compute password  SHA1 and convbase
		hashpass := function_sha1(C_password)
        hashpass16to2 := convBase(hashpass,"0123456789ABCDEF","01")

        //compute Aim
        hrid := convBase(function_sha1(strconv.Itoa(randomnumber_r) + C_id),"0123456789ABCDEF","01")
        Aim := compute_xor(hashpass16to2,hrid)
		
		
	   //echo "Register Succese";
		if(check_exist(C_id)){
			//已有此帳號 無法註冊
			C_state = "此帳號已存在 無法註冊"
			C_gow = "index.gohtml"
		}else{
			//沒有這個帳號  可以註冊
			insert(C_id, strconv.Itoa(randomnumber_r) ,Aim)
			C_state = "已成功註冊"
			C_gow = "index.gohtml"
		}
	}else if(C_action == "Login"){
		//點登入時
		fmt.Println("Login")		
		//check user is exisit or not
		if(check_exist_login(C_id)){
			// get random number r
			randomnumber_r_from_sm := selectrandomnumber(C_id)
			//compute password
			hashpassl := function_sha1(C_password)
			hashpassl16to2 := convBase(hashpassl,"0123456789ABCDEF","01")
			//compute Aim = H(PWUi) ⊕ H(r‖IDSm)
			hridsm := convBase(function_sha1(strconv.Itoa(randomnumber_r_from_sm) + C_id),"0123456789ABCDEF","01")
			Aiml := compute_xor(hashpassl16to2,hridsm)
			//get Aim from smartcard
			get_Aim_from_smartcard := selectAim(C_id)
			
			//對使用者的Aim與smartcard中的Aim進行確認
			if(strconv.Itoa(get_Aim_from_smartcard)==Aiml){
				//echo "<br>";
				//setcookie("smartcarduser", $C_id, time()+420);
				//$_SESSION[cookieID] = $C_id;
				//hashpasssession := function_sha1(C_password)
				//hashpasssession16to2 := convBase(hashpasssession,"0123456789ABCDEF","01")
				//$_SESSION[hashpassword] = $hashpasssession16to2;

				//確認有此帳號 登入成功
				C_state = "登入成功"
				fmt.Println("success")
				inorout = true
				C_gow = "Registration.gohtml"
			}else{
				//Smart Card Verfication Error
				C_state = "Smart Card Verfication Error"
				fmt.Println("Smart Card Verfication Error")
				C_gow = "index.gohtml"
			}
			
			
		}else{
			//帳號密碼錯誤 登入失敗
			C_state = "無此帳號 登入失敗"
			fmt.Println("non")
			C_gow = "index.gohtml"
		}
	}
	
	fmt.Println(C_gow)
	
	
	d := struct{
		C_id,C_password,C_state,C_state1  string
	}{
		//First: fname,
		C_id: C_id,
		C_password: C_password,
		C_state: C_state,
		C_state1: C_gow,
	}

	tpl.ExecuteTemplate(w, "processor.gohtml", d)
}

func insert (C_id string, randomnumber_r string,Aim  string) {
	// insert
	db, err := sql.Open("sqlite3", db_location)
    checkErr(err)
    stmt, err := db.Prepare("INSERT INTO smart_card(User_id, Random_r, Aim) values(?,?,?)")
    checkErr(err)
    res, err := stmt.Exec(C_id, randomnumber_r, Aim)
    checkErr(err)
    id, err := res.LastInsertId()
    checkErr(err)
    fmt.Println(id)	
}

func check_exist (C_id string) bool   {
	// query
	db, err := sql.Open("sqlite3", db_location)
    checkErr(err)
        rows, err := db.Query("SELECT count(*) as countt FROM smart_card where User_id = '" + C_id + "'")
        checkErr(err)
        var countt int
       

        for rows.Next() {
            err = rows.Scan(&countt)
            checkErr(err)
            fmt.Println(countt)
        }
		if(countt != 0){
			return true
		}else{
		
			return false
		}
}

func check_exist_login (C_id string) bool   {
	// query
	db, err := sql.Open("sqlite3", db_location)
    checkErr(err)
		
		
        rows, err := db.Query("SELECT count(*) as countt FROM smart_card where User_id = '" + C_id + "'")
        checkErr(err)
        var countt int
       

        for rows.Next() {
            err = rows.Scan(&countt)
            checkErr(err)
            fmt.Println(countt)
        }
		if(countt != 0){
			return true
		}else{
		
			return false
		}
}

func checkErr(err error) {
    if err != nil {
        panic(err)
    }
}

func out(w http.ResponseWriter, req *http.Request) {
	inorout = false
	pd := pageData{
		Title: "Index Page",
	}

	err := tpl.ExecuteTemplate(w, "out.gohtml", pd)

	if err != nil {
		log.Println("LOGGED", err)
		http.Error(w, "Internal serverrrrr error", http.StatusInternalServerError)
		return
	}
}

func idx(w http.ResponseWriter, req *http.Request) {

	pd := pageData{
		Title: "Index Page",
	}

	err := tpl.ExecuteTemplate(w, "index.gohtml", pd)

	if err != nil {
		log.Println("LOGGED", err)
		http.Error(w, "Internal serverrrrr error", http.StatusInternalServerError)
		return
	}
}

func Register(w http.ResponseWriter, req *http.Request) {

	pd := pageData{
		Title: "Register",
	}

	err := tpl.ExecuteTemplate(w, "Register.gohtml", pd)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func Registration(w http.ResponseWriter, req *http.Request) {
	fmt.Println(inorout)
	pd := pageData{
		Title: "Registration",
	}
	if(inorout){
		err := tpl.ExecuteTemplate(w, "Registration.gohtml", pd)
		if err != nil {
			log.Println(err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}
	

}

func CreatServer(w http.ResponseWriter, req *http.Request) {

	pd := pageData{
		Title: "CreatServer",
	}
	if(inorout){
		var first string
		if req.Method == http.MethodPost {
			first = req.FormValue("fname")
			pd.FirstName = first
		}

		err := tpl.ExecuteTemplate(w, "CreatServer.gohtml", pd)
		if err != nil {
			log.Println(err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}
	
}

func Check_My_Account(w http.ResponseWriter, req *http.Request) {

	pd := pageData{
		Title: "Check_My_Account",
	}
	
	if(inorout){
		var first string
		if req.Method == http.MethodPost {
			first = req.FormValue("fname")
			pd.FirstName = first
		}

		err := tpl.ExecuteTemplate(w, "Check_My_Account.gohtml", pd)
		if err != nil {
			log.Println(err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}		
	}
	
}




func AES_EN (key string, data string) string   {
	key_BYTE := []byte(key)
	result, err := AesEncrypt([]byte(data), key_BYTE)
    if err != nil {
        panic(err)
    }
	var str_re = base64.StdEncoding.EncodeToString(result)
    fmt.Println(str_re)
	return str_re
}

func AES_DE (key string, data_en []byte) string   {
	key_BYTE := []byte(key)
	origData, err := AesDecrypt(data_en, key_BYTE)
    if err != nil {
        panic(err)
    }
    fmt.Println(string(origData))
	return string(origData)
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
    padding := blockSize - len(ciphertext) % blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
    length := len(origData)
    unpadding := int(origData[length-1])
    return origData[:(length - unpadding)]
}

func AesEncrypt(origData, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    blockSize := block.BlockSize()
    origData = PKCS7Padding(origData, blockSize)
    blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
    crypted := make([]byte, len(origData))
    blockMode.CryptBlocks(crypted, origData)
    return crypted, nil
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    blockSize := block.BlockSize()
    blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
    origData := make([]byte, len(crypted))
    blockMode.CryptBlocks(origData, crypted)
    origData = PKCS7UnPadding(origData)
    return origData, nil
}
