package peda

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/whatsauth/watoken"
)

func ReturnStruct(DataStuct any) string {
	jsondata, _ := json.Marshal(DataStuct)
	return string(jsondata)
}

func AmbilDataGeojson(mongoenv, dbname, collname string) string {
	mconn := SetConnection(mongoenv, dbname)
	datagedung := GetAllBangunanLineString(mconn, collname)
	return ReturnStruct(datagedung)
}

func MembuatUser(mongoenv, dbname, collname string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		response.Message = "error parsing application/json: " + err.Error()
	} else {
		response.Status = true
		hash, hashErr := HashPassword(datauser.Password)
		if hashErr != nil {
			response.Message = "Gagal Hash Password" + err.Error()
		}
		InsertUserdata(mconn, collname, datauser.Username, datauser.Role, hash)
		response.Message = "Berhasil Input data"
	}
	return ReturnStruct(response)
}

func MembuatTokenUser(privatekey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		response.Message = "error parsing application/json: " + err.Error()
	} else {
		if IsPasswordValid(mconn, collname, datauser) {
			response.Status = true
			tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(privatekey))
			if err != nil {
				response.Message = "Gagal Encode Token : " + err.Error()
			} else {
				response.Message = "Selamat Datang"
				response.Token = tokenstring
			}
		} else {
			response.Message = "Password Salah"
		}
	}

	return ReturnStruct(response)
}

func MenyimpanTokenUser(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response ResponseDataUser
	mconn := SetConnection(mongoenv, dbname)
	res := new(Response)
	err := json.NewDecoder(r.Body).Decode(&res)
	if err != nil {
		response.Status = false
		response.Message = "error parsing application/json: " + err.Error()
	} else {
		checktoken := watoken.DecodeGetId(os.Getenv(publickey), res.Token)
		compared := CompareUsername(mconn, collname, checktoken)
		if compared != true {
			response.Status = false
			response.Message = "Data Username tidak ada di database"
		} else {
			datauser := GetAllUser(mconn, collname)
			response.Status = true
			response.Message = "data User berhasil diambil"
			response.Data = datauser
		}
	}
	return ReturnStruct(response)
}

func HapusUser(mongoenv, dbname, collname string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		response.Message = "error parsing application/json: " + err.Error()
	} else {
		DeleteUser(mconn, collname, datauser)
		response.Message = "Berhasil Delete data"
	}
	return ReturnStruct(response)
}
