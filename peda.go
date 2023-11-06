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

func MembuatGeojsonPoint(mongoenv, dbname, collname string, r *http.Request) string {
	mconn := SetConnection(mongoenv, dbname)
	var geojsonpoint GeoJsonPoint
	err := json.NewDecoder(r.Body).Decode(&geojsonpoint)
	if err != nil {
		return err.Error()
	}
	PostPoint(mconn, collname, geojsonpoint)
	return ReturnStruct(geojsonpoint)
}

func MembuatGeojsonPolyline(mongoenv, dbname, collname string, r *http.Request) string {
	mconn := SetConnection(mongoenv, dbname)
	var geojsonline GeoJsonLineString
	err := json.NewDecoder(r.Body).Decode(&geojsonline)
	if err != nil {
		return err.Error()
	}
	PostLinestring(mconn, collname, geojsonline)
	return ReturnStruct(geojsonline)
}

func MembuatGeojsonPolygon(mongoenv, dbname, collname string, r *http.Request) string {
	mconn := SetConnection(mongoenv, dbname)
	var geojsonpolygon GeoJsonPolygon
	err := json.NewDecoder(r.Body).Decode(&geojsonpolygon)
	if err != nil {
		return err.Error()
	}
	PostPolygon(mconn, collname, geojsonpolygon)
	return ReturnStruct(geojsonpolygon)
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
		hashRole, hashErrRole := HashRole(datauser.Role)
		if hashErrRole != nil {
			response.Message = "Gagal Hash Role" + err.Error()
		}
		InsertUserdata(mconn, collname, datauser.Username, hash, hashRole)
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
				if IsRoleValid(mconn, collname, datauser) {
					response.Message = "Selamat Datang"
					response.Token = tokenstring
				} else {
					response.Message = "Akun anda tidak memiliki role"
				}
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
