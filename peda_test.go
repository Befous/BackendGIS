package peda

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestUpdateGetData(t *testing.T) {
	mconn := SetConnection("MONGOCONNSTRINGENV", "befous")
	datagedung := GetAllUser(mconn, "user")
	fmt.Println(datagedung)
}

// 	result := GCFCreateHandler(MONGOCONNSTRINGENV, dbname, collectionname, datauser)
// 	fmt.Println(result)
// 	// You can add assertions here to validate the result, or check the database for the created user.
// }

func TestCreateNewUserRole(t *testing.T) {
	var userdata User
	userdata.Username = "befous"
	userdata.Password = "befous"
	userdata.Role = "admin"
	mconn := SetConnection("MONGOCONNSTRINGENV", "befous")
	CreateNewUserRole(mconn, "user", userdata)
}

func TestCreateNewUserToken(t *testing.T) {
	// Create a User struct
	var userdata User
	userdata.Username = "befous"
	userdata.Password = "befous"
	userdata.Role = "admin"

	// Generate private and public keys using watoken.GenerateKey
	privateKey, publicKey := watoken.GenerateKey()

	// Store the private and public keys in the userdata
	userdata.Private = privateKey
	userdata.Publick = publicKey // Corrected the field name from Publick to Public

	// Encode a token using the privateKey
	hasil, err := watoken.Encode("befous", privateKey)
	fmt.Println(hasil, err)
	if err != nil {
		t.Errorf("Failed to create user and token: %v", err)
	} else {
		t.Logf("User and token created successfully")

		// Assuming you have a MongoDB client and a database connection, use the client and connection to insert the userdata
		// Replace "yourDatabaseName" with your actual database name
		client, err := mongo.NewClient(options.Client().ApplyURI("MONGOCONNSTRINGENV"))
		if err != nil {
			t.Errorf("Failed to create MongoDB client: %v", err)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			err = client.Connect(ctx)
			if err != nil {
				t.Errorf("Failed to connect to MongoDB: %v", err)
			} else {
				// Use the database name and collection name where you want to insert the user data
				db := client.Database("befous")
				collection := db.Collection("user")

				_, err = collection.InsertOne(ctx, userdata)
				if err != nil {
					t.Errorf("Failed to insert user data into MongoDB: %v", err)
				} else {
					t.Logf("User data inserted into MongoDB successfully")
				}
			}
		}
	}
}

func TestDeleteUser(t *testing.T) {

	mconn := SetConnection("MONGOCONNSTRINGENV", "befous")
	var userdata User
	userdata.Username = "befous"
	DeleteUser(mconn, "user", userdata)
}

func TestGFCPostHandlerUser(t *testing.T) {
	mconn := SetConnection("MONGOCONNSTRINGENV", "befous")
	var userdata User
	userdata.Username = "befous"
	userdata.Password = "befous"
	userdata.Role = "admin"
	CreateNewUserRole(mconn, "user", userdata)
}

func TestFunciionUser(t *testing.T) {
	mconn := SetConnection("MONGOCONNSTRINGENV", "befous")
	var userdata User
	userdata.Username = "befous"
	userdata.Password = "befous"
	userdata.Role = "admin"
	CreateNewUserRole(mconn, "user", userdata)
}

func TestProduct(t *testing.T) {
	mconn := SetConnection("MONGOCONNSTRINGENV", "befous")
	var productdata Product
	productdata.Nomorid = 1
	productdata.Name = "befous"
	productdata.Description = "befous"
	productdata.Price = 1000
	productdata.Size = "XL"
	productdata.Stock = 100
	productdata.Image = "https://images3.alphacoders.com/165/thumb-1920-165265.jpg"
	CreateNewProduct(mconn, "product", productdata)
}

func TestAllProduct(t *testing.T) {
	mconn := SetConnection("MONGOCONNSTRINGENV", "befous")
	product := GetAllProduct(mconn, "product")
	fmt.Println(product)
}

func TestGeneratePasswordHashh(t *testing.T) {
	password := "secret"
	hash, _ := HashPassword(password) // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)

	match := CheckPasswordHash(password, hash)
	fmt.Println("Match:   ", match)
}
func TestHashFunctionn(t *testing.T) {
	mconn := SetConnection("MONGOCONNSTRINGENV", "befous")
	var userdata User
	userdata.Username = "befous"
	userdata.Password = "befous"

	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mconn, "user", filter)
	fmt.Println("Mongo User Result: ", res)
	hash, _ := HashPassword(userdata.Password)
	fmt.Println("Hash Password : ", hash)
	match := CheckPasswordHash(userdata.Password, res.Password)
	fmt.Println("Match:   ", match)

}
func TestFindUser(t *testing.T) {
	var userdata User
	userdata.Username = "befous"
	mconn := SetConnection("MONGOCONNSTRINGENV", "befous")
	res := FindUser(mconn, "user", userdata)
	fmt.Println(res)
}

func TestGeneratePasswordHash(t *testing.T) {
	password := "ganteng"
	hash, _ := HashPassword(password) // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)
	match := CheckPasswordHash(password, hash)
	fmt.Println("Match:   ", match)
}
func TestGeneratePrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("befous", privateKey)
	fmt.Println(hasil, err)
}

func TestHashFunction(t *testing.T) {
	mconn := SetConnection("MONGOCONNSTRINGENV", "befous")
	var userdata User
	userdata.Username = "befous"
	userdata.Password = "befous"

	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mconn, "user", filter)
	fmt.Println("Mongo User Result: ", res)
	hash, _ := HashPassword(userdata.Password)
	fmt.Println("Hash Password : ", hash)
	match := CheckPasswordHash(userdata.Password, res.Password)
	fmt.Println("Match:   ", match)

}

func TestIsPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOCONNSTRINGENV", "befous")
	var userdata User
	userdata.Username = "befous"
	userdata.Password = "befous"

	anu := IsPasswordValid(mconn, "user", userdata)
	fmt.Println(anu)
}
