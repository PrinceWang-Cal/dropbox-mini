package proj2

// CS 161 Project 2 Fall 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	K_private userlib.PKEDecKey //128 bytes seems appropriate
	K_sign userlib.DSSignKey
	Salt []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type File struct {
	Ownername_and_tag []byte
	Data_list []uuid.UUID
	Data_list_tag []byte
	Accesstoken_dictionary map[string][][]byte
	Accesstree_dictionary map[string][]string
	Access_tag_dictionary map[string][]byte
	All_accesstoken_map map[string][]byte
	All_accesstoken_map_tag []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//generate RSA encryption keys
	var K_public userlib.PKEEncKey
	var K_private userlib.PKEDecKey
	K_public, K_private, _ = userlib.PKEKeyGen()
	err = userlib.KeystoreSet(hex.EncodeToString([]byte(username)) + "public key" ,K_public)
	if err != nil {
		userlib.DebugMsg("The username already exists!")
		return nil, err
	}

	//generate RSA digital signature keys
	var K_sign userlib.DSSignKey
	var K_verify userlib.DSVerifyKey
	K_sign, K_verify, _ = userlib.DSKeyGen()
	userlib.KeystoreSet(hex.EncodeToString([]byte(username)) + "verify key",K_verify)

	//generate a random salt
	var salt []byte = userlib.RandomBytes(4)

	//create user struct
	userdata = User{username, password, K_private, K_sign, salt}

	//create user_tokenmap
	var user_tokenmap map[string][][]byte
	user_tokenmap = make(map[string][][]byte)

	//generate K_master
	var K_master []byte = userlib.Argon2Key([]byte(password), salt, 16)

	//Generate keys for user_struct
	var K_encrypt_user_struct []byte
	K_encrypt_user_struct, _ = userlib.HashKDF(K_master, []byte("Encrypt user struct"))
	K_encrypt_user_struct = K_encrypt_user_struct[:16]
	var K_HMAC_user_struct []byte
	K_HMAC_user_struct, _ = userlib.HashKDF(K_master, []byte("HMAC user struct"))
	K_HMAC_user_struct = K_HMAC_user_struct[:16]

	//Serialize user struct
	var marshal_user_struct []byte
	marshal_user_struct, _ = json.Marshal(userdata)

	//Encrypt user_struct
	var R_struct []byte = AESWithPadding(K_encrypt_user_struct, marshal_user_struct)
	var T_struct []byte
	T_struct, _ = userlib.HMACEval(K_HMAC_user_struct, R_struct)

	//store user struct
	var UUID_struct uuid.UUID
	ID_struct := userlib.Hash([]byte(username + "struct"))
	UUID_struct, _ = uuid.FromBytes(ID_struct[:16])
	userlib.DatastoreSet(UUID_struct, append(append(salt[:], R_struct...), T_struct[:]...)) //append S, R_struct and T_struct

	StoreUserTokenmap(K_master,user_tokenmap,username)

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//retrieve the corresponding UUID
	var UUID_struct uuid.UUID
	ID_struct := userlib.Hash([]byte(username+"struct"))
	UUID_struct, _ = uuid.FromBytes(ID_struct[:16])


	//retrieve data from datastore, username might be invalid
	var stored_data []byte
	var user_found bool
	stored_data, user_found = userlib.DatastoreGet(UUID_struct)
	if !user_found {
		userlib.DebugMsg("The username is not found")
		err = errors.New("The username is not found.")
		return nil, err
	}

	if len(stored_data) < 68 {
		userlib.DebugMsg("Datastore is hacked!")
		err = errors.New("Datastore is hacked!")
		return nil, err
	}

	var salt []byte = stored_data[:4]
	var K_master []byte = GenerateKMaster(password, salt)

	R_struct := stored_data[4:len(stored_data)-64]
	T_struct := stored_data[len(stored_data)-64:]

	var K_encrypt_user_struct []byte
	K_encrypt_user_struct, _ = userlib.HashKDF(K_master, []byte("Encrypt user struct"))
	K_encrypt_user_struct = K_encrypt_user_struct[:16]

	var K_HMAC_user_struct []byte
	K_HMAC_user_struct, _ = userlib.HashKDF(K_master, []byte("HMAC user struct"))
	K_HMAC_user_struct = K_HMAC_user_struct[:16]

	if !VerifyIntegrity(K_HMAC_user_struct, R_struct, T_struct) {
		userlib.DebugMsg("Incorrect password, or datastore is hacked!")
		err = errors.New("Incorrect password, or datastore is hacked!")
		return nil, err
	}

	user_struct_bytes := DecAESWithPadding(K_encrypt_user_struct, R_struct)

	err = json.Unmarshal(user_struct_bytes, userdataptr)
	if err != nil {
		return userdataptr, err
	}

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	//define user_tokenmap for later reference
	var user_tokenmap map[string][][]byte
	user_tokenmap, ok := getAndVerifyUserTokenmap(userdata)

	if !ok {
		return
	}

	//check if the filename already existed for the user
	fileID_local := userlib.Hash([]byte(filename))
	fileID_local_string := hex.EncodeToString(fileID_local[:]) // convert to string because key is of type string

	if _, found := user_tokenmap[fileID_local_string]; found {
		// if we find the key, this means we are overriding an existing file
		StoreFileOverwrite(filename,data,user_tokenmap,userdata.Username)
		return
	}

	var K_master []byte = GenerateKMaster(userdata.Password, userdata.Salt)
	// if we do not find the key, this means we are creating a new file
	StoreFileNew(filename, data, user_tokenmap, userdata.Username, K_master)
	return
}


func StoreFileOverwrite(filename string, data []byte, user_tokenmap map[string][][]byte, username string) {

	file_struct, K_file, fileID_global, ok := getAndVerifyFileStruct(filename, user_tokenmap, username)
	if !ok {
		return
	}

	for _, u := range file_struct.Data_list {
		userlib.DatastoreDelete(u)
	}

	var K_file_data_HMAC []byte
	K_file_data_HMAC, _ = userlib.HashKDF(K_file, append([]byte("HMAC"),byte(0)))
	K_file_data_HMAC = K_file_data_HMAC[:16]

	var K_file_data_list_HMAC []byte
	K_file_data_list_HMAC, _ = userlib.HashKDF(K_file, []byte("HMAC"))
	K_file_data_list_HMAC = K_file_data_list_HMAC[:16]

	//Encrypt the data
	var C_data []byte
	C_data = AESWithPadding(K_file, data)

	//compute tag for the data
	var T_data []byte
	T_data, _ = userlib.HMACEval(K_file_data_HMAC, C_data)

	//compute the id of the data
	h := userlib.Hash(append(fileID_global[:], byte(0)))
	var DataID_hash []byte = h[:]
	var data_ID uuid.UUID
	data_ID, _ = uuid.FromBytes(DataID_hash[:16])

	//store the data into Datastore
	userlib.DatastoreSet(data_ID, append(T_data, C_data...))

	// recompute data list and data list tag
	Data_list := make([]uuid.UUID, 1)
	Data_list[0] = data_ID
	Data_list_bytes, _ := json.Marshal(Data_list)
	Data_list_tag, _ := userlib.HMACEval(K_file_data_list_HMAC,Data_list_bytes)

	file_struct.Data_list = Data_list
	file_struct.Data_list_tag = Data_list_tag

	file_struct_bytes, _ := json.Marshal(file_struct)
	i,_ := uuid.FromBytes(fileID_global)
	userlib.DatastoreSet(i,file_struct_bytes)

	return

}

func StoreFileNew(filename string, data []byte, user_tokenmap map[string][][]byte, username string, K_master []byte) {

	//compute fileID_global
	h := userlib.Hash([]byte(filename+username))
	var fileID_hash []byte = h[:]
	var fileID_global uuid.UUID
	fileID_global, _ = uuid.FromBytes(fileID_hash[:16])

	//generate the keys for this file
	var K_file []byte
	K_file, _ = userlib.HashKDF(K_master, append([]byte(filename), userlib.RandomBytes(32)...))
	K_file = K_file[:16]

	var K_file_data_list_HMAC []byte
	K_file_data_list_HMAC, _ = userlib.HashKDF(K_file, []byte("HMAC"))
	K_file_data_list_HMAC = K_file_data_list_HMAC[:16]

	var K_file_data_HMAC []byte
	K_file_data_HMAC, _ = userlib.HashKDF(K_file, append([]byte("HMAC"),byte(0)))
	K_file_data_HMAC = K_file_data_HMAC[:16]

	var K_file_all_accesstoken_HMAC []byte
	K_file_all_accesstoken_HMAC, _ = userlib.HashKDF(K_file, []byte("All accesstoken HMAC"))
	K_file_all_accesstoken_HMAC = K_file_all_accesstoken_HMAC[:16]

	var K_file_ownername_HMAC []byte
	K_file_ownername_HMAC, _ = userlib.HashKDF(K_file, []byte("ownername"))
	K_file_ownername_HMAC = K_file_ownername_HMAC[:16]


	//Encrypt the data
	var C_data []byte
	C_data = AESWithPadding(K_file, data)

	//compute tag for the data
	var T_data []byte
	T_data, _ = userlib.HMACEval(K_file_data_HMAC, C_data)

	//compute the id of the data
	d := userlib.Hash(append(fileID_global[:], byte(0)))
	var DataID_hash []byte = d[:]
	var data_ID uuid.UUID
	data_ID, _ = uuid.FromBytes(DataID_hash[:16])

	//store the data into Datastore
	userlib.DatastoreSet(data_ID, append(T_data, C_data...))

	//compute access token
	var Accesstoken []byte
	Accesstoken, _ = userlib.HashKDF(K_file, append([]byte(username), userlib.RandomBytes(32)[:]...))
	Accesstoken = Accesstoken[:16]

	var Accesstoken_HMAC []byte
	Accesstoken_HMAC, _ = userlib.HashKDF(Accesstoken, []byte("HMAC"))
	Accesstoken_HMAC = Accesstoken_HMAC[:16]

	var Accesstoken_tree_HMAC []byte
	Accesstoken_tree_HMAC, _ = userlib.HashKDF(Accesstoken, []byte("tree HMAC"))
	Accesstoken_tree_HMAC = Accesstoken_tree_HMAC[:16]

	//store user_tokenmap
	fileID_local := userlib.Hash([]byte(filename))
	fileID_local_string := hex.EncodeToString(fileID_local[:])
	content := make([][]byte , 2)
	content[0] = Accesstoken
	content[1] = fileID_global[:]
	user_tokenmap[fileID_local_string] = content

	//store the user_tokenmap back
	StoreUserTokenmap(K_master, user_tokenmap, username)

	//create file struct instance
	Ownername := []byte(username)
	Ownername_tag, _ := userlib.HMACEval(K_file_ownername_HMAC,Ownername)
	Ownername_and_tag := append(Ownername,Ownername_tag...)

	Data_list := make([]uuid.UUID, 1)
	Data_list[0] = data_ID

	Data_list_bytes, _ := json.Marshal(Data_list)
	Data_list_tag, _ := userlib.HMACEval(K_file_data_list_HMAC,Data_list_bytes)

	var Accesstoken_dictionary map[string][][]byte
	Accesstoken_dictionary = make(map[string][][]byte)
	C_filekey := AESWithPadding(Accesstoken, K_file)
	T_filekey, _ := userlib.HMACEval(Accesstoken_HMAC, C_filekey)
	arr := make([][]byte , 2)
	arr[0] = C_filekey
	arr[1] = T_filekey
	Accesstoken_dictionary[username] = arr

	var Accesstree_dictionary map[string][]string
	Accesstree_dictionary = make(map[string][]string)
	children := make([]string, 0)
	Accesstree_dictionary[username] = children

	var Access_tag_dictionary map[string][]byte
	Access_tag_dictionary = make(map[string][]byte)
	Accesstree_dictionary_bytes, _ := json.Marshal(Accesstree_dictionary[username])
	tag, _ := userlib.HMACEval(Accesstoken_tree_HMAC,Accesstree_dictionary_bytes)
	Access_tag_dictionary[username] = tag

	var All_accesstoken_map map[string][]byte
	All_accesstoken_map = make(map[string][]byte)
	public_key, _ := userlib.KeystoreGet(hex.EncodeToString([]byte(username)) + "public key")
	token_enc, _ := userlib.PKEEnc(public_key, Accesstoken)
	All_accesstoken_map[username] = token_enc

	var All_accesstoken_map_tag []byte
	All_accesstoken_map_bytes, _ := json.Marshal(All_accesstoken_map)
	All_accesstoken_map_tag, _ = userlib.HMACEval(K_file_all_accesstoken_HMAC, All_accesstoken_map_bytes)

	file_struct := File{Ownername_and_tag, Data_list, Data_list_tag, Accesstoken_dictionary, Accesstree_dictionary, Access_tag_dictionary, All_accesstoken_map, All_accesstoken_map_tag}

	file_struct_bytes, _ := json.Marshal(file_struct)
	userlib.DatastoreSet(fileID_global,file_struct_bytes)

}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	fileID_local := userlib.Hash([]byte(filename))
	fileID_local_string := hex.EncodeToString(fileID_local[:])

	//access tokenmap
	var user_tokenmap map[string][][]byte
	user_tokenmap, ok := getAndVerifyUserTokenmap(userdata)
	if !ok {
		userlib.DebugMsg("tokenmap retrieval and verification failed.")
		return  errors.New("Tokenmap verification and retrieval failed.")
	}

	//check fileID_local is in user_tokenmap
	if _, found := user_tokenmap[fileID_local_string]; !found {
		userlib.DebugMsg("File not in user's tokenmap")
		return errors.New("File not in user's tokenmap; does not exist.")
	}

	//get file content and verify file struct
	var file_struct *File
	var K_file []byte
	file_struct, K_file,fileID_global,ok := getAndVerifyFileStruct(filename, user_tokenmap, userdata.Username)

	if !ok {
		userlib.DebugMsg("File integrity breached")
		return  errors.New("File integrity breached.")
	}

	//now store the new data node
	var i int = len(file_struct.Data_list)
	var K_file_data_HMAC []byte
	K_file_data_HMAC, _ = userlib.HashKDF(K_file, append([]byte("HMAC"),byte(i)))
	K_file_data_HMAC = K_file_data_HMAC[:16]

	C_data := AESWithPadding(K_file, data)
	var T_data []byte
	T_data, _ = userlib.HMACEval(K_file_data_HMAC, C_data)


	d := userlib.Hash(append(fileID_global[:], byte(i)))
	var DataID_hash []byte = d[:]
	var data_ID uuid.UUID
	data_ID, _ = uuid.FromBytes(DataID_hash[:16])

	//store the data into Datastore
	userlib.DatastoreSet(data_ID, append(T_data, C_data...))

	file_struct.Data_list = append(file_struct.Data_list, data_ID)

	//recompute tag
	var K_file_data_list_HMAC []byte
	K_file_data_list_HMAC, _ = userlib.HashKDF(K_file, []byte("HMAC"))
	K_file_data_list_HMAC = K_file_data_list_HMAC[:16]
	Data_list_bytes, _ := json.Marshal(file_struct.Data_list)
	Data_list_tag, _ := userlib.HMACEval(K_file_data_list_HMAC,Data_list_bytes)
	file_struct.Data_list_tag = Data_list_tag

	file_struct_bytes, _ := json.Marshal(file_struct)
	u,_ := uuid.FromBytes(fileID_global)
	userlib.DatastoreSet(u, file_struct_bytes)

	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	data = make([]byte, 0)

	fileID_local := userlib.Hash([]byte(filename))
	fileID_Local_string := hex.EncodeToString(fileID_local[:])

	//access tokenmap
	var user_tokenmap map[string][][]byte
	user_tokenmap, ok := getAndVerifyUserTokenmap(userdata)
	if !ok {
		userlib.DebugMsg("tokenmap retrieval and verification failed.")
		return nil, errors.New("Tokenmap verification and retrieval failed.")
	}

	//check fileID_local is in user_tokenmap
	if _, found := user_tokenmap[fileID_Local_string]; !found {
		userlib.DebugMsg("File not in user's tokenmap")
		return nil, errors.New("File not in user's tokenmap.")
	}

	//get file content and verify file struct
	var file_struct *File
	var K_file []byte
	file_struct, K_file, _, ok = getAndVerifyFileStruct(filename, user_tokenmap, userdata.Username)

	if !ok {
		userlib.DebugMsg("File integrity breached")
		return nil, errors.New("File integrity breached.")
	}

	for i, data_ID := range(file_struct.Data_list) {
		//verify integrity of each content node
		var K_file_data_HMAC []byte
		K_file_data_HMAC, _ = userlib.HashKDF(K_file, append([]byte("HMAC"),byte(i)))
		K_file_data_HMAC = K_file_data_HMAC[:16]

		stored_data, ok := userlib.DatastoreGet(data_ID)
		if !ok {
			userlib.DebugMsg("data node not found")
			return nil, errors.New("Node not found in datastore.")
		}

		if len(stored_data) < 64 {
			return nil, errors.New("Node has been tampered.")
		}
		var T_data []byte = stored_data[:64]
		var C_data []byte = stored_data[64:]
		if !VerifyIntegrity(K_file_data_HMAC, C_data, T_data) {
			userlib.DebugMsg("Node has been tampered.")
			return nil, errors.New("Node has been tampered.")
		}
		var decrypted_data []byte = DecAESWithPadding(K_file, C_data)
		data = append(data, decrypted_data...)
	}

	return data, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	var K_public userlib.PKEEncKey
	K_public, ok := userlib.KeystoreGet(hex.EncodeToString([]byte(recipient))+"public key")
	if !ok {
		userlib.DebugMsg("Recipient not found!")
		return "", errors.New("Recipient not found!")
	}
	K_sign := userdata.K_sign

	//get file id local
	fileID_local_string := getFileIDLocal(filename)

	//access usertokenmap
	var user_tokenmap map[string][][]byte
	user_tokenmap, ok = getAndVerifyUserTokenmap(userdata)
	if !ok {
		userlib.DebugMsg("tokenmap retrieval and verification failed.")
		return  "", errors.New("Tokenmap verification and retrieval failed.")
	}

	//check fileID_local is in user_tokenmap
	if _, found := user_tokenmap[fileID_local_string]; !found {
		userlib.DebugMsg("File not in user's tokenmap")
		return "", errors.New("File not in user's tokenmap; does not exist.")
	}

	//get the file
	Accesstoken := user_tokenmap[fileID_local_string][0]
	fileID_global := user_tokenmap[fileID_local_string][1]

	//unmarshall file struct
	u, _ := uuid.FromBytes(fileID_global)
	file_struct_bytes, ok := userlib.DatastoreGet(u)
	if !ok {
		userlib.DebugMsg("File does not exist; or might be tampered/deleted.")
		return "", errors.New("File does not exist; or might be tampered/deleted.")
	}
	var file_struct File
	file_struct_ptr := &file_struct
	error_local := json.Unmarshal(file_struct_bytes, file_struct_ptr)
	if error_local != nil {
		userlib.DebugMsg("File struct failed to unmarshal, might be tampered.")
		return "", errors.New("File struct failed to unmarshal, might be tampered.")
	}

	if _, ok := file_struct.Accesstoken_dictionary[userdata.Username]; !ok {
		return "", errors.New("User doesn't exist in access tree!")
	}
	C_filekey := file_struct.Accesstoken_dictionary[userdata.Username][0]
	T_filekey := file_struct.Accesstoken_dictionary[userdata.Username][1]

	Accesstoken_HMAC, _ := userlib.HashKDF(Accesstoken, []byte("HMAC"))
	Accesstoken_HMAC = Accesstoken_HMAC[:16]
	if !VerifyIntegrity(Accesstoken_HMAC, C_filekey, T_filekey) { // rejected
		return "", errors.New("integrity of accesstoken tampered")
	}

	//compute all the keys needed
	K_file := DecAESWithPadding(Accesstoken, C_filekey)

	K_file_all_accesstoken_HMAC, _ := userlib.HashKDF(K_file, []byte("All accesstoken HMAC"))
	K_file_all_accesstoken_HMAC = K_file_all_accesstoken_HMAC[:16]

	//create new accesstoken
	new_Accesstoken, _ := userlib.HashKDF(K_file, append([]byte(recipient), userlib.RandomBytes(32)[:]...))
	new_Accesstoken = new_Accesstoken[:16]

	//compute new Accesstoken HMAC and tree HMAC
	new_Accesstoken_HMAC, _ := userlib.HashKDF(new_Accesstoken, []byte("HMAC"))
	new_Accesstoken_HMAC = new_Accesstoken_HMAC[:16]

	new_Accesstoken_tree_HMAC , _ := userlib.HashKDF(new_Accesstoken, []byte("tree HMAC"))
	new_Accesstoken_tree_HMAC = new_Accesstoken_tree_HMAC[:16]


	//new entries in file_sturct

	//new entry in Accesstoken_dictionary
	C_filekey_new := AESWithPadding(new_Accesstoken, K_file)
	T_filekey_new, _ := userlib.HMACEval(new_Accesstoken_HMAC, C_filekey_new)

	arr := make([][]byte , 2)
	arr[0] = C_filekey_new
	arr[1] = T_filekey_new
	file_struct.Accesstoken_dictionary[recipient] = arr

	//new entry in Accesstree_dictionary
	new_list := append(file_struct.Accesstree_dictionary[userdata.Username], recipient)
	file_struct.Accesstree_dictionary[userdata.Username] = new_list
	children := make([]string, 0)
	file_struct.Accesstree_dictionary[recipient] = children

	//new entry in Access_tag_dictionary
	var Accesstoken_tree_HMAC []byte
	Accesstoken_tree_HMAC, _ = userlib.HashKDF(Accesstoken, []byte("tree HMAC"))
	Accesstoken_tree_HMAC = Accesstoken_tree_HMAC[:16]

	s_data, _ := json.Marshal(new_list)
	tag_S, _ := userlib.HMACEval(Accesstoken_tree_HMAC, s_data)

	s_empty_list, _ := json.Marshal(children)
	tag_R, _ := userlib.HMACEval(new_Accesstoken_tree_HMAC, s_empty_list)

	file_struct.Access_tag_dictionary[userdata.Username] = tag_S
	file_struct.Access_tag_dictionary[recipient] = tag_R

	//new entry in the file_struct.all_accesstokenmap

	//verify the file_struct.ownernameandtag has integrity
	if !verifyOwner(file_struct.Ownername_and_tag, K_file) {
		userlib.DebugMsg("file_struct owner field got changed")
		return "", errors.New("integrity of file owner tampered")
	}

	var owner_name_byte []byte = file_struct.Ownername_and_tag[:len(file_struct.Ownername_and_tag)-64]
	var owner_name_string string = hex.EncodeToString(owner_name_byte)


	public_key_recipient, _ := userlib.KeystoreGet(owner_name_string + "public key")
	encrypted_new_token, _ := userlib.PKEEnc(public_key_recipient, new_Accesstoken)
	file_struct.All_accesstoken_map[recipient] = encrypted_new_token

	//new entry in All_accesstoken_map_tag
	all_accesstoken_map_byte, _ := json.Marshal(file_struct.All_accesstoken_map)
	tag_map, _ := userlib.HMACEval(K_file_all_accesstoken_HMAC, all_accesstoken_map_byte)
	file_struct.All_accesstoken_map_tag = tag_map

	file_struct_bytes, _ = json.Marshal(file_struct)
	i,_ := uuid.FromBytes(fileID_global)
	userlib.DatastoreSet(i,file_struct_bytes)

	var K_session []byte
	K_session = userlib.RandomBytes(32)[:]

	//create message
	message := make([][]byte, 3)
	message[0] = AESWithPadding(K_session, append(new_Accesstoken, fileID_global...))
	message[1], _ = userlib.PKEEnc(K_public, K_session)

	//
	h := userlib.Hash(append(new_Accesstoken, fileID_global...))
	message[2], _ = userlib.DSSign(K_sign, h[:])

	message_byte, _ := json.Marshal(message)

	return hex.EncodeToString(message_byte), nil
}


// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.

func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {

	//get file id local
	fileID_local_string := getFileIDLocal(filename)

	//access usertokenmap
	user_tokenmap, ok := getAndVerifyUserTokenmap(userdata)
	if !ok {
		userlib.DebugMsg("tokenmap retrieval and verification failed.")
		return errors.New("Tokenmap verification and retrieval failed.")
	}

	//retrieve user_tokenmap and verify

	if _, found := user_tokenmap[fileID_local_string]; found {
		// if we find the key, this means we can't receive this duplicate file
		_, e := userdata.LoadFile(filename)
		if e == nil {
			return errors.New("File with same name detected!")
		}
	}

	K_private := userdata.K_private

	K_verify, ok := userlib.KeystoreGet(hex.EncodeToString([]byte(sender))+"verify key")
	if !ok {
		userlib.DebugMsg("Sender not found!")
		return errors.New("Sender not found!")
	}

	magic_string_bytes, err := hex.DecodeString(magic_string)
	if err != nil {
		return  errors.New("Message is hacked!")
	}


	message := make([][]byte, 3)
	err = json.Unmarshal(magic_string_bytes, &message)
	if err != nil {
		return  errors.New("Message is hacked!")
	}

	if len(message) != 3 {
		return  errors.New("Message is hacked!")
	}
	A := message[0]
	B := message[1]
	C := message[2]

	K_session, err := userlib.PKEDec(K_private, B)
	if err != nil {
		return  errors.New("Message is hacked!")
	}

	M := DecAESWithPadding(K_session, A)

	M_hash := userlib.Hash(M[:])
	err = userlib.DSVerify(K_verify, M_hash[:], C)
	if err != nil {
		return  errors.New("Message is hacked!")
	}

	if len(M) < 16 {
		return  errors.New("Message is hacked!")
	}
	Accesstoken := M[:16]
	fileID_global := M[16:]

	content := make([][]byte , 2)
	content[0] = Accesstoken
	content[1] = fileID_global[:]
	user_tokenmap[fileID_local_string] = content

	var K_master []byte = GenerateKMaster(userdata.Password, userdata.Salt)

	StoreUserTokenmap(K_master, user_tokenmap, userdata.Username)

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	//get file id local
	fileID_local_string := getFileIDLocal(filename)

	//access usertokenmap
	var user_tokenmap map[string][][]byte
	user_tokenmap, ok := getAndVerifyUserTokenmap(userdata)
	if !ok {
		userlib.DebugMsg("tokenmap retrieval and verification failed.")
		return  errors.New("Tokenmap verification and retrieval failed.")
	}

	if _, found := user_tokenmap[fileID_local_string]; !found {
		// if we find the key, this means we can't receive this duplicate file
		return  errors.New("File not found!")
	}

	//get the file
	Accesstoken := user_tokenmap[fileID_local_string][0]
	fileID_global := user_tokenmap[fileID_local_string][1]

	//unmarshall file struct
	u, _ := uuid.FromBytes(fileID_global)
	file_struct_bytes, ok := userlib.DatastoreGet(u)
	if !ok {
		return  errors.New("Getting file struct failed.")
	}
	var file_struct File
	file_struct_ptr := &file_struct
	err_temp := json.Unmarshal(file_struct_bytes, file_struct_ptr)
	if err_temp != nil {
		return  errors.New("Unmarshal file struct failed.")
	}

	if _, ok = file_struct.Accesstoken_dictionary[userdata.Username]; !ok {
		return errors.New("File struct is hacked!")
	}
	C_filekey := file_struct.Accesstoken_dictionary[userdata.Username][0]
	T_filekey := file_struct.Accesstoken_dictionary[userdata.Username][1]

	Accesstoken_HMAC, _ := userlib.HashKDF(Accesstoken, []byte("HMAC"))
	Accesstoken_HMAC = Accesstoken_HMAC[:16]
	if !VerifyIntegrity(Accesstoken_HMAC, C_filekey, T_filekey) { // rejected
		return  errors.New("File struct hacked!")
	}

	//compute all the keys needed
	K_file := DecAESWithPadding(Accesstoken, C_filekey)

	K_file_all_accesstoken_HMAC, _ := userlib.HashKDF(K_file, []byte("All accesstoken HMAC"))
	K_file_all_accesstoken_HMAC = K_file_all_accesstoken_HMAC[:16]

	All_accesstoken_map_bytes, _ := json.Marshal(file_struct.All_accesstoken_map)
	ok = VerifyIntegrity(K_file_all_accesstoken_HMAC, All_accesstoken_map_bytes, file_struct.All_accesstoken_map_tag)
	if !ok {
		return  errors.New("File struct hacked!")
	}

	// compute all the accesstokens and store them into a map
	var name_to_token map[string][]byte
	name_to_token = make(map[string][]byte)
	for k, v := range file_struct.All_accesstoken_map {
		a, e := userlib.PKEDec(userdata.K_private, v)
		if e != nil {
			return errors.New("Decryption of accesstokens failed!")
		}
		name_to_token[k] = a
	}

	// remove the target user and all corresponding children, along with verifying integrity
	ok = DeleteUserFromFile(&file_struct, target_username, name_to_token)
	if !ok {
		return errors.New("Access tree tampered!")
	}

	// find and remove the target user from the parent's array, recompute tags.
	for i, name := range file_struct.Accesstree_dictionary[userdata.Username] {
		if name == target_username {
			file_struct.Accesstree_dictionary[userdata.Username] = append(file_struct.Accesstree_dictionary[userdata.Username][:i], file_struct.Accesstree_dictionary[userdata.Username][i+1:]...)
			break
		}
	}

	Accesstoken_tree_HMAC, _ := userlib.HashKDF(Accesstoken, []byte("tree HMAC"))
	Accesstoken_tree_HMAC = Accesstoken_tree_HMAC[:16]
	Accesstree_dictionary_bytes, _ := json.Marshal(file_struct.Accesstree_dictionary[userdata.Username])
	tag_1, _ := userlib.HMACEval(Accesstoken_tree_HMAC,Accesstree_dictionary_bytes)
	file_struct.Access_tag_dictionary[userdata.Username] = tag_1

	// compute new K_file
	var K_master []byte = GenerateKMaster(userdata.Password, userdata.Salt)
	new_K_file, _ := userlib.HashKDF(K_master, append([]byte(filename), userlib.RandomBytes(32)...))
	new_K_file = new_K_file[:16]

	// recompute ownername and tag
	new_K_file_ownername_HMAC, _ := userlib.HashKDF(new_K_file, []byte("ownername"))
	new_K_file_ownername_HMAC = new_K_file_ownername_HMAC[:16]
	Ownername := []byte(userdata.Username)
	Ownername_tag, _ := userlib.HMACEval(new_K_file_ownername_HMAC,Ownername)
	Ownername_and_tag := append(Ownername,Ownername_tag...)
	file_struct.Ownername_and_tag = Ownername_and_tag

	// recompute accesstoken dictionary for all users
	recompute_accesstoken_dictionary(&file_struct,new_K_file, name_to_token)

	// recompute/encrypt data list and tag
	err = recompute_datalist_and_tag(&file_struct,new_K_file, K_file)
	if err != nil {
		return err
	}

	//recompute All_accesstoken_map_tag
	new_K_file_all_accesstoken_HMAC, _ := userlib.HashKDF(new_K_file, []byte("All accesstoken HMAC"))
	new_K_file_all_accesstoken_HMAC = new_K_file_all_accesstoken_HMAC[:16]
	All_accesstoken_map_bytes, _ = json.Marshal(file_struct.All_accesstoken_map)
	tag_2, _ := userlib.HMACEval(new_K_file_all_accesstoken_HMAC, All_accesstoken_map_bytes)
	file_struct.All_accesstoken_map_tag = tag_2

	//upload new file struct
	file_struct_bytes, _ = json.Marshal(file_struct)

	fileID_global_uuid, _ := uuid.FromBytes(fileID_global)
	userlib.DatastoreSet(fileID_global_uuid,file_struct_bytes)

	return nil
}

// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS
// HELPER FUNCTIONS

// performs AES with correct padding. For details view lecture 6 slide 25
func AESWithPadding(key []byte, plaintext []byte) (enc []byte) {
	plaintext_length := len(plaintext)
	blocksize := userlib.AESBlockSize
	pad := blocksize - plaintext_length % blocksize
	if pad == 0 {
		pad = userlib.AESBlockSize
	}
	for i := 0; i < pad; i++ {
		plaintext = append(plaintext, byte(pad))
	}
	enc = userlib.SymEnc(key, userlib.RandomBytes(userlib.AESBlockSize), plaintext)
	return enc
}

// generates the master key based on input password and salt
func GenerateKMaster(password string, salt []byte) (K_master []byte) {
	K_master = userlib.Argon2Key([]byte(password), salt, 16)
	return K_master
}

// verifies integrity
func VerifyIntegrity(key_Hmac []byte, content []byte, tag []byte) (ok bool) {
	var new_HMAC []byte
	new_HMAC, _ = userlib.HMACEval(key_Hmac, content)
	return userlib.HMACEqual(new_HMAC, tag)
}

// performs aes decryption and handles removing padding
func DecAESWithPadding(key []byte, ciphertext []byte) (dec []byte) {
	dec = userlib.SymDec(key, ciphertext)
	pad := int(dec[len(dec) - 1])
	dec = dec[:len(dec) - pad]
	return dec
}

func getAndVerifyFileStruct(filename string, user_tokenmap map[string][][]byte, username string) (file_struct_ptr *File, K_file []byte, fileID_global []byte, ok bool) {

	fileID_local := userlib.Hash([]byte(filename))
	fileID_local_string := hex.EncodeToString(fileID_local[:]) // convert to string because key is of type string
	Accesstoken := user_tokenmap[fileID_local_string][0]
	fileID_global = user_tokenmap[fileID_local_string][1]

	//unmarshall file struct
	u, _ := uuid.FromBytes(fileID_global)
	file_struct_bytes, ok := userlib.DatastoreGet(u)
	if !ok {
		return nil, nil, nil,false
	}
	var file_struct File
	file_struct_ptr = &file_struct
	err := json.Unmarshal(file_struct_bytes, file_struct_ptr)
	if err != nil {
		return nil, nil, nil,false
	}

	if _, ok = file_struct.Accesstoken_dictionary[username]; !ok {
		return nil, nil, nil,false
	}
	C_filekey := file_struct.Accesstoken_dictionary[username][0]
	T_filekey := file_struct.Accesstoken_dictionary[username][1]

	Accesstoken_HMAC, _ := userlib.HashKDF(Accesstoken, []byte("HMAC"))
	Accesstoken_HMAC = Accesstoken_HMAC[:16]
	if !VerifyIntegrity(Accesstoken_HMAC, C_filekey, T_filekey) { // rejected
		return nil, nil, nil,false
	}

	K_file = DecAESWithPadding(Accesstoken, C_filekey)
	K_file_data_list_HMAC, _ := userlib.HashKDF(K_file, []byte("HMAC"))
	K_file_data_list_HMAC = K_file_data_list_HMAC[:16]
	Data_list_bytes, _ := json.Marshal(file_struct.Data_list)
	if !VerifyIntegrity(K_file_data_list_HMAC, Data_list_bytes, file_struct.Data_list_tag) { // rejected
		return nil, nil, nil,false
	}

	return file_struct_ptr, K_file, fileID_global,true

}


func getAndVerifyUserTokenmap(userdata *User) (user_tokenmap map[string][][]byte ,ok bool){
	//Retrieve user_tokenmap
	ID_map := userlib.Hash([]byte(userdata.Username + "tokenmap"))
	UUID_tokenmap, _ := uuid.FromBytes(ID_map[:16])
	stored_data, ok := userlib.DatastoreGet(UUID_tokenmap)
	if !ok {
		return nil, false
	}

	//compute the keys we needed for verification
	var K_master []byte = GenerateKMaster(userdata.Password, userdata.Salt)
	if len(stored_data) < 64 {
		return nil, false
	}
	R_tokenmap := stored_data[:len(stored_data)-64]
	T_tokenmap := stored_data[len(stored_data)-64:]

	var K_encrypt_user_tokenmap []byte
	K_encrypt_user_tokenmap, _ = userlib.HashKDF(K_master, []byte("Encrypt user tokenmap"))
	K_encrypt_user_tokenmap = K_encrypt_user_tokenmap[:16]

	var K_HMAC_user_tokenmap []byte
	K_HMAC_user_tokenmap, _ = userlib.HashKDF(K_master, []byte("HMAC user tokenmap"))
	K_HMAC_user_tokenmap = K_HMAC_user_tokenmap[:16]

	//Verify the integrity of tokenmap
	if !VerifyIntegrity(K_HMAC_user_tokenmap, R_tokenmap, T_tokenmap) {
		userlib.DebugMsg("Tokenmap tampered!")
		return nil, false
	}

	//decrypt the tokenmap
	user_tokenmap_bytes := DecAESWithPadding(K_encrypt_user_tokenmap, R_tokenmap)
	err := json.Unmarshal(user_tokenmap_bytes, &user_tokenmap)
	if err != nil {
		userlib.DebugMsg("tokenmap cannot be unmarshaled")
		return nil, false
	}

	return user_tokenmap, true

}


func StoreUserTokenmap(K_master []byte, user_tokenmap map[string][][]byte, username string) {
	//Generate key for user_tokenmap
	var K_encrypt_user_tokenmap []byte
	K_encrypt_user_tokenmap, _ = userlib.HashKDF(K_master, []byte("Encrypt user tokenmap"))
	K_encrypt_user_tokenmap = K_encrypt_user_tokenmap[:16]
	var K_HMAC_user_tokenmap []byte
	K_HMAC_user_tokenmap, _ = userlib.HashKDF(K_master, []byte("HMAC user tokenmap"))
	K_HMAC_user_tokenmap = K_HMAC_user_tokenmap[:16]

	//Serialize user_tokenmap
	var marshal_user_tokenmap []byte
	marshal_user_tokenmap, _ = json.Marshal(user_tokenmap)

	//Encrypt user_tokenmap
	var R_tokenmap []byte = AESWithPadding(K_encrypt_user_tokenmap, marshal_user_tokenmap)
	var T_tokenmap []byte
	T_tokenmap, _ = userlib.HMACEval(K_HMAC_user_tokenmap, R_tokenmap)

	//store user tokenmap
	var UUID_tokenmap uuid.UUID
	ID_tokenmap := userlib.Hash([]byte(username + "tokenmap"))
	UUID_tokenmap, _ = uuid.FromBytes(ID_tokenmap[:16])
	userlib.DatastoreSet(UUID_tokenmap, append(R_tokenmap, T_tokenmap...))

}


func getFileIDLocal (filename string) (fileID_local_string string) {
	fileID_local := userlib.Hash([]byte(filename))
	fileID_local_string = hex.EncodeToString(fileID_local[:])
	return fileID_local_string
}

func verifyOwner(name_and_tag []byte, K_file []byte) (ok bool) {
	var K_file_ownername_HMAC []byte
	K_file_ownername_HMAC, _ = userlib.HashKDF(K_file, []byte("ownername"))
	K_file_ownername_HMAC = K_file_ownername_HMAC[:16]

	if len(name_and_tag) < 64 {
		return false
	}
	var name []byte = name_and_tag[:len(name_and_tag)-64]
	var tag []byte = name_and_tag[len(name_and_tag)-64:]
	return VerifyIntegrity(K_file_ownername_HMAC, name, tag)
}



func DeleteUserFromFile(file_struct *File, username string, name_to_token map[string][]byte) (ok bool) {

	// first verify the integrity of the accesstree
	if _, ok := file_struct.Accesstree_dictionary[username]; !ok {
		return false
	}
	children := file_struct.Accesstree_dictionary[username]
	accesstoken := name_to_token[username]
	Accesstoken_tree_HMAC, _ := userlib.HashKDF(accesstoken, []byte("tree HMAC"))
	Accesstoken_tree_HMAC = Accesstoken_tree_HMAC[:16]
	children_bytes, _ := json.Marshal(children)
	ok = VerifyIntegrity(Accesstoken_tree_HMAC, children_bytes, file_struct.Access_tag_dictionary[username])
	if !ok {
		return ok
	}

	for _, name := range children {
		ok = DeleteUserFromFile(file_struct,name,name_to_token)
		if !ok {
			return ok
		}
	}

	delete(file_struct.Accesstoken_dictionary, username)
	delete(file_struct.Accesstree_dictionary, username)
	delete(file_struct.Access_tag_dictionary, username)
	delete(file_struct.All_accesstoken_map, username)

	return true
}

func recompute_accesstoken_dictionary(file_struct *File, K_file []byte, name_to_token map[string][]byte) {

	for k, _ := range file_struct.Accesstoken_dictionary {
		Accesstoken := name_to_token[k]
		Accesstoken_HMAC, _ := userlib.HashKDF(Accesstoken, []byte("HMAC"))
		Accesstoken_HMAC = Accesstoken_HMAC[:16]
		C_filekey := AESWithPadding(Accesstoken, K_file)
		T_filekey, _ := userlib.HMACEval(Accesstoken_HMAC, C_filekey)
		arr := make([][]byte , 2)
		arr[0] = C_filekey
		arr[1] = T_filekey
		file_struct.Accesstoken_dictionary[k] = arr
	}

}

func recompute_datalist_and_tag(file_struct *File, K_file []byte, old_K_file []byte) (err error) {
	K_file_data_list_HMAC, _ := userlib.HashKDF(K_file, []byte("HMAC"))
	K_file_data_list_HMAC = K_file_data_list_HMAC[:16]
	Data_list_bytes, _ := json.Marshal(file_struct.Data_list)
	Data_list_tag, _ := userlib.HMACEval(K_file_data_list_HMAC,Data_list_bytes)
	file_struct.Data_list_tag = Data_list_tag

	for i, data_ID := range file_struct.Data_list {
		var old_K_file_data_HMAC []byte
		old_K_file_data_HMAC, _ = userlib.HashKDF(old_K_file, append([]byte("HMAC"),byte(i)))
		old_K_file_data_HMAC = old_K_file_data_HMAC[:16]

		stored_data, ok := userlib.DatastoreGet(data_ID)
		if !ok {
			userlib.DebugMsg("data node not found")
			return errors.New("Node not found in datastore.")
		}

		if len(stored_data) < 64 {
			return errors.New("Node has been tampered.")
		}
		var T_data []byte = stored_data[:64]
		var C_data []byte = stored_data[64:]
		if !VerifyIntegrity(old_K_file_data_HMAC, C_data, T_data) {
			userlib.DebugMsg("Node has been tampered.")
			return errors.New("Node has been tampered.")
		}
		var decrypted_data []byte = DecAESWithPadding(old_K_file, C_data)

		// recompute the encrypted data and new tag
		var K_file_data_HMAC []byte
		K_file_data_HMAC, _ = userlib.HashKDF(K_file, append([]byte("HMAC"),byte(i)))
		K_file_data_HMAC = K_file_data_HMAC[:16]
		C_data = AESWithPadding(K_file, decrypted_data)
		T_data, _ = userlib.HMACEval(K_file_data_HMAC, C_data)

		//store back
		userlib.DatastoreSet(data_ID, append(T_data, C_data...))
	}

	return nil
}