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

func AmbilDataGeojson(mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	if r.Header.Get("token") == os.Getenv("TOKEN") {
		mconn := SetConnection(mongoenv, dbname)
		datagedung := GetAllBangunanLineString(mconn, collname)
		err := json.NewDecoder(r.Body).Decode(&datagedung)
		if err != nil {
			response.Message = "error parsing application/json: " + err.Error()
		} else {
			response.Message = "Data berhasil diambil"
		}
	} else {
		response.Message = "Token Salah"
	}
	return ReturnStruct(response)
}

func MembuatGeojsonPoint(mongoenv, dbname, collname string, r *http.Request) string {
	var atmessage PostToken
	if r.Header.Get("token") == os.Getenv("TOKEN") {
		mconn := SetConnection(mongoenv, dbname)
		var geojsonpoint GeoJsonPoint
		err := json.NewDecoder(r.Body).Decode(&geojsonpoint)
		if err != nil {
			atmessage.Response = "error parsing application/json: " + err.Error()
		} else {
			PostPoint(mconn, collname, geojsonpoint)
			atmessage, _ = PostStructWithToken[PostToken]("Token", os.Getenv("TOKEN"), geojsonpoint, "https://asia-southeast2-befous.cloudfunctions.net/Befous-MembuatGeojsonPoint-Token")
		}
	} else {
		atmessage.Response = "Token Salah"
	}
	return ReturnStruct(atmessage)
}

func MembuatGeojsonPolyline(mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	if r.Header.Get("token") == os.Getenv("TOKEN") {
		mconn := SetConnection(mongoenv, dbname)
		var geojsonline GeoJsonLineString
		err := json.NewDecoder(r.Body).Decode(&geojsonline)
		if err != nil {
			response.Message = "error parsing application/json: " + err.Error()
		} else {
			PostLinestring(mconn, collname, geojsonline)
			response.Message = "Data polyline berhasil masuk"
		}
	} else {
		response.Message = "Token Salah"
	}
	return ReturnStruct(response)
}

func MembuatGeojsonPolygon(mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	if r.Header.Get("token") == os.Getenv("TOKEN") {
		mconn := SetConnection(mongoenv, dbname)
		var geojsonpolygon GeoJsonPolygon
		err := json.NewDecoder(r.Body).Decode(&geojsonpolygon)
		if err != nil {
			response.Message = "error parsing application/json: " + err.Error()
		} else {
			PostPolygon(mconn, collname, geojsonpolygon)
			response.Message = "Data polygon berhasil masuk"
		}
	} else {
		response.Message = "Token Salah"
	}
	return ReturnStruct(response)
}

func RegistrasiUser(mongoenv, dbname, collname string, r *http.Request) string {
	var response Credential
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if usernameExists(mongoenv, dbname, datauser) {
		response.Status = false
		response.Message = "Username telah dipakai"
	} else {
		response.Status = true
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
	}
	return ReturnStruct(response)
}

func LoginUser(privatekey, mongoenv, dbname, collname string, r *http.Request) string {
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
