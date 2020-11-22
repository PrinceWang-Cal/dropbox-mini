package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func difference(before_keys []uuid.UUID, after_keys []uuid.UUID) (c []uuid.UUID) {
	c = make([]uuid.UUID, 0)
	for _, after_key := range after_keys {
		found := false
		for _, before_key := range before_keys {
			if before_key == after_key {
				found = true
			}
		}
		if !found {
			c = append(c, after_key)
		}
	}
	return c
}

func GetKeyArray() (c []uuid.UUID) {
	before_map := userlib.DatastoreGetMap()
	before_keys := make([]uuid.UUID, 0)
	for k, _ := range before_map {
		before_keys = append(before_keys, k)
	}
	return before_keys
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}


func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}

func TestInitUser(t *testing.T) {
	clear()

	_, err := InitUser("User1111111111111111111111111111", "ppppp")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u, err2 := InitUser("User1111111111111111111111111111", "passwrod2")
	if err2 == nil || u != nil{
		t.Error("Creating two users with same username should return error!", err2)
		return
	}
}

func TestGetUser(t *testing.T) {
	clear()

	_, err := InitUser("User1", "ppppp")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u, e := GetUser("User", "ppppp")
	if e == nil || u!= nil {
		t.Error("Nonexistent username should return error", e)
		return
	}

	u, e = GetUser("User1", "p!")
	if e == nil || u != nil {
		t.Error("Incorrect password should return error!")
		return
	}

	u, e = GetUser("User1", "ppppp")
	if e != nil || u == nil {
		t.Error("Cannot retrieve user struct!")
		return
	}

	u_2, e := GetUser("User1", "ppppp")
	if e != nil || u_2 == nil {
		t.Error("Multiple instantiation of users isn't working!")
		return
	}

	_, e = InitUser("Adver!", "ppppp")
	copy_map := userlib.DatastoreGetMap()
	keys := make([]uuid.UUID, 0)
	for k, _ := range copy_map {
		keys = append(keys, k)
	}
	temp0, _ := userlib.DatastoreGet(keys[0])
	temp1, _ := userlib.DatastoreGet(keys[1])
	temp2, _ := userlib.DatastoreGet(keys[2])
	temp3, _ := userlib.DatastoreGet(keys[3])
	userlib.DatastoreSet(keys[0], temp1)
	userlib.DatastoreSet(keys[1], temp0)
	userlib.DatastoreSet(keys[2], temp3)
	userlib.DatastoreSet(keys[3], temp2)
	adv_struct, e := GetUser("Adver!", "ppppp")
	if e == nil || adv_struct != nil {
		t.Error("Adversary works by swapping values!")
		return
	}

	userlib.DatastoreSet(keys[0], userlib.RandomBytes(32))
	userlib.DatastoreSet(keys[1], userlib.RandomBytes(32))
	userlib.DatastoreSet(keys[2], userlib.RandomBytes(32))
	userlib.DatastoreSet(keys[3], userlib.RandomBytes(32))
	u , e = GetUser("User1", "ppppp")
	if e == nil || u != nil {
		t.Error("Tamper not detected!")
		return
	}

	userlib.DatastoreSet(keys[0], userlib.RandomBytes(3332))
	userlib.DatastoreSet(keys[1], userlib.RandomBytes(3332))
	userlib.DatastoreSet(keys[2], userlib.RandomBytes(3332))
	userlib.DatastoreSet(keys[3], userlib.RandomBytes(3332))
	u , e = GetUser("User1", "ppppp")
	if e == nil || u != nil {
		t.Error("Tamper not detected!")
		return
	}


}

func TestStoreFile(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")

	v1 := []byte("In our current design, since a malicious attacker can decrypt their own user structure, they could modify the structure, set themselves as owner of a file that they were not shared access to, and then encrypt/MAC it and publish it to the datastore, effectively making them owner of any file. This does not necessarily grant them permission to decrypt the file (they still can only decrypt files where they have key access), but this grants them the permission to share for any file.")
	u.StoreFile("Speech", v1)

	v2, err := u.LoadFile("Speech")
	if err != nil {
		t.Error("Failed to upload/download", err)
		return
	}
	if !reflect.DeepEqual(v1, v2) {
		t.Error("Downloaded file is not the same", v1, v2)
		return
	}

	v3 := []byte("Some other content!")
	u.StoreFile("Trash", v3)

	v4, err := u.LoadFile("Trash")
	if err != nil {
		t.Error("Failed to upload/download second file", err)
		return
	}
	if !reflect.DeepEqual(v3, v4) {
		t.Error("Downloaded second file is not the same", v3, v4)
		return
	}

	v5 := []byte("This is overridden!")
	u.StoreFile("Speech", v5)
	v6, err := u.LoadFile("Speech")
	if err != nil {
		t.Error("Failed to override file!", err)
		return
	}
	if !reflect.DeepEqual(v5, v6) {
		t.Error("Downloaded file is not overridden", v5, v6)
		return
	}

	v4, err = u.LoadFile("Trash")
	if err != nil {
		t.Error("Failed to upload/download file after overriding other files", err)
		return
	}
	if !reflect.DeepEqual(v3, v4) {
		t.Error("Downloaded file is not the same after overriding other files", v3, v4)
		return
	}

	u_copy, _ := GetUser("alice", "fubar")
	u.StoreFile("Third file", []byte("Some other content!"))
	content, err := u_copy.LoadFile("Third file")
	if err != nil {
		t.Error("Failed to upload/download file with second instantiation of same user!", err)
		return
	}
	if !reflect.DeepEqual(content, []byte("Some other content!")) {
		t.Error("Downloaded file is not the same for second instantiation of user!", content, []byte("Some other content!"))
		return
	}

	ov := []byte("OVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDEOVERRIDDE")
	u.StoreFile("Third file", ov)
	content, err = u_copy.LoadFile("Third file")
	if err != nil {
		t.Error("Failed to upload/download file with second instantiation of same user!", err)
		return
	}
	if !reflect.DeepEqual(content, ov) {
		t.Error("Downloaded file is not the same for second instantiation of user!", content, ov)
		return
	}

	u_2, _ := InitUser("Second", "Second")
	u_2.StoreFile("Third file", []byte("This is a test!"))
	b, err := u_2.LoadFile("Nonexistent!")
	if err == nil || b != nil {
		t.Error("Getting a nonexistent file should return error!", content, ov)
		return
	}
	b, _ = u_2.LoadFile("Third file")
	if !reflect.DeepEqual(b, []byte("This is a test!")) {
		t.Error("Different users with same filename is problematic!", b, []byte("This is a test!"))
		return
	}
	b, _ = u.LoadFile("Third file")
	if !reflect.DeepEqual(b, ov) {
		t.Error("Different users with same filename is problematic!", b, ov)
		return
	}

	u_copy.StoreFile("231813562365384068865541227471581454583108276306947939351816843241592454751996698949991569948700125923969894225396759379047520602489014818832113194067374194856827428413507619256245974964241185182931967721673199499359204503787777827094879029762434378356817953391561575446304913220028861821404557", ov)
	content, err = u.LoadFile("231813562365384068865541227471581454583108276306947939351816843241592454751996698949991569948700125923969894225396759379047520602489014818832113194067374194856827428413507619256245974964241185182931967721673199499359204503787777827094879029762434378356817953391561575446304913220028861821404557")
	if err != nil {
		t.Error("Large filename is problematic!")
		return
	}
	if !reflect.DeepEqual(content, ov) {
		t.Error("Large filename is problematic!", b, ov)
		return
	}

	u_adversary, _ := InitUser("alicee", "adve")
	c, err := u_adversary.LoadFile("Trash")
	if err == nil || c != nil {
		t.Error("Adversary wins by accessing others' file!")
		return
	}

}
func TestStoreFile2(t *testing.T) {
	clear()
	u1, _ := InitUser("alice", "fubar")
	u2, _ := InitUser("bob", "barfu")
	u1.StoreFile("File1", []byte("content1"))
	u2.StoreFile("File1", []byte("content2"))
	data1, _ := u1.LoadFile("File1")
	data2, _ := u2.LoadFile("File1")
	if reflect.DeepEqual(data1, data2) {
		t.Error("File should not be equal")
		return
	}
}


func TestTamper(t *testing.T) {
	clear ()

	a, _ := InitUser("a", "password")
	before_keys := GetKeyArray()
	a.StoreFile("File", userlib.RandomBytes(64))
	after_keys := GetKeyArray()

	new_keys := difference(before_keys,after_keys)
	for _, k := range new_keys {
		userlib.DatastoreSet(k,userlib.RandomBytes(128))
	}

	_, err := a.LoadFile("File")
	if err == nil {
		t.Error("Didn't detect breached file!")
		return
	}

	clear()
	a, _ = InitUser("a", "password")
	a.StoreFile("File", userlib.RandomBytes(64))
	b, _ := InitUser("b", "b")
	token, _ := a.ShareFile("File", "b")
	_ = b.ReceiveFile("File", "a", token)
	before_keys = GetKeyArray()
	_ = a.AppendFile("File", userlib.RandomBytes(32))
	after_keys = GetKeyArray()

	new_keys = difference(before_keys,after_keys)
	for _, k := range new_keys {
		userlib.DatastoreSet(k,userlib.RandomBytes(28))
	}

	_, err = a.LoadFile("File")
	if err == nil {
		t.Error("Didn't detect breached file!")
		return
	}

	_, err = b.LoadFile("File")
	if err == nil {
		t.Error("Didn't detect breached file!")
		return
	}


}


func TestUserAppendFile(t *testing.T) {
	clear()

	//Append an existing file
	u1, _ := InitUser("alice", "foobar")
	v1 := []byte("This is a file.")
	u1.StoreFile("Alice's File", v1)

	a1 := []byte("We append some bytes")
	err := u1.AppendFile("Alice's File", a1)
	if err != nil {
		t.Error("AppendFile failed to append to an existing file")
		return
	}

	//append to a non-existent file
	err = u1.AppendFile("Bob's File", a1)
	if err == nil {
		t.Error("AppendFile failed, detect that file does not exist")
		return
	}

	var v2 []byte
	v2, err = u1.LoadFile("Alice's File")

	if !reflect.DeepEqual(v2, append(v1, a1...)) {
		t.Error("File not correctly appended!")
		return
	}

	//Two user instances. User A append the file, and user b should loadfile and
	//see the change immediately
	u2, _ := InitUser("bob", "bob foobar")
	token, e := u1.ShareFile("Alice's File", "bob")
	if e != nil  {
		t.Error("Fail to share an existing file")
		return
	}


	err = u2.ReceiveFile("Alice's File", "alice", token)
	if err != nil {
		t.Error("Fail to receive a shared file")
		return
	}
	v3, e3 := u2.LoadFile("Alice's File")
	if e3 != nil {
		t.Error("Fail to load a received file")
		return
	}

	//check if this is the same as the latest version
	if !reflect.DeepEqual(v2, v3) {
		t.Error("bob's loaded file is not to Alice's latest version", v2, v3)
		return
	}

	//now append another segment to Alice's file
	a2 := []byte("Some new information.")
	err = u1.AppendFile("Alice's File", a2)
	if err != nil {
		t.Error("Failed to append Alice's File")
		return
	}

	//now reload the file for bob
	var v4 []byte
	v4, err = u2.LoadFile("Alice's File")
	if err != nil {
		t.Error("bob failed to load Alice's File")
		return
	}

	//check the correctness of the content
	if !reflect.DeepEqual(v4, append(v3, a2...)) {
		t.Error("Newly loaded file for bob does not have the most up to date content", v4, append(v3, a2...))
		return
	}

	//Test bulk append
	final, _ := InitUser("Final", "Final")
	data := []byte("bob's loaded file is not to Alice's latest version")
	final.StoreFile("Final file!", data)
	for i := 1; i < 500; i++ {
		data = append(data, []byte("bob's loaded file is not to Alice's latest version")...)
		_ = final.AppendFile("Final file!", []byte("bob's loaded file is not to Alice's latest version"))
	}
	output, _ := final.LoadFile("Final file!")
	if !reflect.DeepEqual(output, data) {
		t.Error("Bulk append does not work!")
		return
	}

}

func TestEmptyFilenameAndContents(t *testing.T) {
	clear()

	a, _ := InitUser("a", "a")
	a.StoreFile("",[]byte(""))
	content, err := a.LoadFile("")
	if err != nil || !reflect.DeepEqual([]byte(""), content) {
		t.Error("Empty filename or empty content doesn't work!")
		return
	}

	err = a.AppendFile("", []byte("actual content"))
	if err != nil {
		t.Error("Appending to empty file fails!")
		return
	}
	content, err = a.LoadFile("")
	if err != nil || !reflect.DeepEqual([]byte("actual content"), content) {
		t.Error("Empty filename or empty content append doesn't work!")
		return
	}

	a.StoreFile("", []byte(""))
	content, err = a.LoadFile("")
	if err != nil || !reflect.DeepEqual([]byte(""), content) {
		t.Error("Empty filename or empty content doesn't work!")
		return
	}


}

func TestUserShareFile(t *testing.T) {
	clear()

	//Initization of users
	alice, _ := InitUser("alice", "foobar")
	bob, _ := InitUser("bob", "barfoo")

	//Store a file for Alice
	alice.StoreFile("F1", []byte("All for party."))

	//Share a file to another user. Another user should be able to receive it
	token, e := alice.ShareFile("F1", "bob")
	if e != nil {
		t.Error("Fail to share an existing file")
		return
	}

	test, e := alice.ShareFile("F1", "Doesn't exist!")
	if e == nil || test != "" {
		t.Error("Sharing to non existent recipient should trigger error!")
		return
	}

	e = bob.ReceiveFile("F1", "alice", token)
	if e != nil {
		t.Error("Fail to receive a shared file")
		return
	}

	e = bob.ReceiveFile("F1", "No exist!", token)
	if e == nil {
		t.Error("Receiving from nonexistent sender should trigger error!")
		return
	}

	e = bob.ReceiveFile("F1", "alice", token)
	if e == nil {
		t.Error("Receiving same file multiple times should trigger error!")
		return
	}

	//Share a non-existent file
	token, e = alice.ShareFile("Ghost File", "bob")
	if e == nil || token != "" {
		t.Error("Error: Should not be able to share a non-existent file")
		return
	}

	//Share to a non-existent user
	var f2_content []byte = []byte("Deep dark fantasy")
	alice.StoreFile("F2", f2_content)

	token, e = alice.ShareFile("F2", "carol")
	if e == nil || token != "" {
		t.Error("Should not be able to share with a non-existent user")
		return
	}

	//Share a file to another user. Before receiving it, tamper the token.
	token, e = alice.ShareFile("F2", "bob")
	if e != nil || token == "" {
		t.Error("Fail to share an existing file")
		return
	}

	//tamper the token
	token_tampered := "tamperedToken" //token being tampered
	e = bob.ReceiveFile("F2","alice", token_tampered)
	if e == nil {
		t.Error("Fail stop a tampered token from being used")
		return
	}

	token_tampered = "=== RUN   TestStoreFile\n2020/11/17 18:04:59 18:04:59.22319 File not in user's tokenmap\n2020/11/17 18:04:59 18:04:59.57802 File not in user's tokenmap\n--- PASS: TestStoreFile (1.35s)\n=== RUN   TestUserAppendFile\n2020/11/17 18:04:59 18:04:59.78156 File not in user's tokenmap\n--- PASS: TestUserAppendFile (7.07s)\n=== RUN   TestUserShareFile\n2020/11/17 18:05:07 18:05:07.25392 Recipient not found!\n2020/11/17 18:05:07 18:05:07.34036 File not in user's tokenmap\n2020/11/17 18:05:07 18:05:07.36444 Recipient not found!\n--- PASS: TestUserShareFile (0.74s)\nPASS" //token being tampered
	e = bob.ReceiveFile("F2","alice", token_tampered)
	if e == nil {
		t.Error("Fail stop a tampered token from being used")
		return
	}

	token_tampered = ""
	e = bob.ReceiveFile("F2","alice", token_tampered)
	if e == nil {
		t.Error("Fail stop a tampered token from being used")
		return
	}

	//User A changes the file. User B should load it without error since integrity is preserved. Content should be the latest
	_ = alice.AppendFile("F1", []byte("Some more new bytes"))
	v1, _ := alice.LoadFile("F1")
	v2, _ := bob.LoadFile("F1")
	if !reflect.DeepEqual(v1, v2) {
		t.Error("bob's loaded file is not to Alice's latest version", v1, v2)
		return
	}

	//Share a file to User B, and User B append the file. User A should see the change
	_ = bob.AppendFile("F1", []byte("Changes made by bob."))
	v3 := append(v1, []byte("Changes made by bob.")...)

	v4, _ := alice.LoadFile("F1")
	if !reflect.DeepEqual(v3, v4) {
		t.Error("alice's loaded file is not to bob's latest version")
		return
	}

	actual := []byte("All for party.Some more new bytesChanges made by bob.")
	if !reflect.DeepEqual(actual, v4) {
		t.Error("Shared user fails to append to file!")
		return
	}

	//Store a file, but with the same file name as the file name this user received
	//from another user. This also causes overwriting
	new_content := []byte("This should overwrite the old F1 file by Alice")
	bob.StoreFile("F1", new_content)

	v5, _ := alice.LoadFile("F1")
	v6, _ := bob.LoadFile("F1")
	if !reflect.DeepEqual(new_content, v5) {
		t.Error("alice's loaded file is not to bob's latest version")
		return
	}
	if !reflect.DeepEqual(new_content, v6) {
		t.Error("bob's loaded file is not to bob's latest version")
		return
	}

	nick, _ := InitUser("nick", "strong password")
	token, _ = bob.ShareFile("F1", "nick")
	e = nick.ReceiveFile("File", "bob", token)
	if e != nil {
		t.Error("Failed to share to a third person!")
		return
	}
	content, _ := nick.LoadFile("File")
	if !reflect.DeepEqual(new_content, content) {
		t.Error("Third person fails to see file!")
		return
	}
	_ = nick.AppendFile("File", []byte("!!!!!!!More data!!!"))
	new_content = append(new_content,[]byte("!!!!!!!More data!!!")...)
	content, _ = alice.LoadFile("F1")
	if !reflect.DeepEqual(new_content, content) {
		t.Error("Third person fails to append file!")
		return
	}

}


func TestRevokeFile(t *testing.T) {
	clear()

	// file1
	// u1 -> u2, u3
	// u2 -> u4, u5
	// u3 -> u6

	// file2
	// u6 -> u7
	// u7 -> u1, u2
	u1, _ := InitUser("u1", "u1_password")
	u2, _ := InitUser("u2", "u2_password")
	u3, _ := InitUser("u3", "u3_password")
	u4, _ := InitUser("u4", "u4_password")
	u5, _ := InitUser("u5", "u5_password")
	u6, _ := InitUser("u6", "u6_password")
	u7, _ := InitUser("u7", "u7_password")

	file1_data := []byte("")
	u1.StoreFile("File1", file1_data)
	File1_token, _ := u1.ShareFile("File1","u2")
	_ = u2.ReceiveFile("File1","u1", File1_token)
	File1_token, _ = u1.ShareFile("File1","u3")
	_ = u3.ReceiveFile("File1","u1", File1_token)
	File1_token, _ = u2.ShareFile("File1","u4")
	_ = u4.ReceiveFile("File1","u2", File1_token)
	File1_token, _ = u2.ShareFile("File1","u5")
	_ = u5.ReceiveFile("File1","u2", File1_token)
	File1_token, _ = u3.ShareFile("File1","u6")
	_ = u6.ReceiveFile("File1","u3", File1_token)

	file2_data := userlib.RandomBytes(32)
	u6.StoreFile("File2", file2_data)
	File2_token, _ := u6.ShareFile("File2", "u7")
	_ = u7.ReceiveFile("File2", "u6", File2_token)
	File2_token, _ = u7.ShareFile("File2", "u1")
	_ = u1.ReceiveFile("File2", "u7", File2_token)
	File2_token, _ = u7.ShareFile("File2", "u2")
	_ = u2.ReceiveFile("File2", "u7", File2_token)


	// now test basic access controls for file 1
	data, err := u1.LoadFile("File1")
	if !reflect.DeepEqual(data, file1_data) || err != nil {
		t.Error("Fails to load correct contents of shared file!")
		return
	}
	data, err = u2.LoadFile("File1")
	if !reflect.DeepEqual(data, file1_data) || err != nil {
		t.Error("Fails to load correct contents of shared file!")
		return
	}
	data, err = u3.LoadFile("File1")
	if !reflect.DeepEqual(data, file1_data) || err != nil {
		t.Error("Fails to load correct contents of shared file!")
		return
	}
	data, err = u4.LoadFile("File1")
	if !reflect.DeepEqual(data, file1_data) || err != nil {
		t.Error("Fails to load correct contents of shared file!")
		return
	}
	data, err = u5.LoadFile("File1")
	if !reflect.DeepEqual(data, file1_data) || err != nil {
		t.Error("Fails to load correct contents of shared file!")
		return
	}
	data, err = u6.LoadFile("File1")
	if !reflect.DeepEqual(data, file1_data) || err != nil {
		t.Error("Fails to load correct contents of shared file!")
		return
	}
	data, err = u7.LoadFile("File1")
	if err == nil || data != nil {
		t.Error("Person not shared with has access to file!")
		return
	}

	// test revoke for file 1
	err = u1.RevokeFile("File1", "u3")
	if err != nil {
		t.Error("Failed to revoke access!")
		return
	}
	data, err = u3.LoadFile("File1")
	if err == nil || data != nil {
		t.Error("User shouldn't access file after revoked!")
		return
	}

	_, err = u3.ShareFile("File1", "u6")
	if err == nil {
		t.Error("User shouldn't be able to share a file after revoked!")
		return
	} //NEW_CODE

	data, err = u6.LoadFile("File1")
	if err == nil || data != nil {
		t.Error("User shouldn't access file after revoked!")
		return
	}
	u3.StoreFile("File1",[]byte("New content!"))
	data, err = u2.LoadFile("File1")
	if !reflect.DeepEqual(data, file1_data) || err != nil {
		t.Error("User shouldn't re-store file after revoked!")
		return
	}
	u6.StoreFile("File1",[]byte("New content!"))
	data, err = u2.LoadFile("File1")
	if !reflect.DeepEqual(data, file1_data) || err != nil {
		t.Error("User shouldn't re-store file after revoked!")
		return
	}
	err = u3.AppendFile("File1", []byte("Append!"))
	if err == nil {
		t.Error("User shouldn't append file after revoked!")
		return
	}
	err = u6.AppendFile("File1", []byte("Append!"))
	if err == nil {
		t.Error("User shouldn't append file after revoked!")
		return
	}
	data, err = u2.LoadFile("File1")
	if !reflect.DeepEqual(data, file1_data) || err != nil {
		t.Error("User shouldn't append file after revoked!")
		return
	}

	file1_data = append(file1_data, []byte("new stuff!")...)
	_ = u5.AppendFile("File1", []byte("new stuff!"))
	data, err = u4.LoadFile("File1")
	if !reflect.DeepEqual(data, file1_data) || err != nil {
		t.Error("User shouldn't append file after revoked!")
		return
	}

	err = u1.RevokeFile("File1", "u2")
	if err != nil {
		t.Error("Failed to revoke access!")
		return
	}

	data, err = u2.LoadFile("File1")
	if err == nil || data != nil {
		t.Error("User shouldn't access file after revoked!")
		return
	}
	data, err = u4.LoadFile("File1")
	if err == nil || data != nil {
		t.Error("User shouldn't access file after revoked!")
		return
	}
	data, err = u5.LoadFile("File1")
	if err == nil || data != nil {
		t.Error("User shouldn't access file after revoked!")
		return
	}
	u2.StoreFile("File1",[]byte("New content!"))
	u4.StoreFile("File1",[]byte("New content!"))
	u5.StoreFile("File1",[]byte("New content!"))
	data, err = u1.LoadFile("File1")
	if !reflect.DeepEqual(data, file1_data) || err != nil {
		t.Error("User shouldn't re-store file after revoked!")
		return
	}
	err = u4.AppendFile("File1", []byte("Append!"))
	if err == nil {
		t.Error("User shouldn't append file after revoked!")
		return
	}
	err = u5.AppendFile("File1", []byte("Append!"))
	if err == nil {
		t.Error("User shouldn't append file after revoked!")
		return
	}
	data, err = u1.LoadFile("File1")
	if !reflect.DeepEqual(data, file1_data) || err != nil {
		t.Error("User shouldn't append file after revoked!")
		return
	}


	// now test basic access control for file 2
	data, err = u1.LoadFile("File2")
	if !reflect.DeepEqual(data, file2_data) || err != nil {
		t.Error("Fails to load correct contents of shared file!")
		return
	}
	data, err = u2.LoadFile("File2")
	if !reflect.DeepEqual(data, file2_data) || err != nil {
		t.Error("Fails to load correct contents of shared file!")
		return
	}
	data, err = u6.LoadFile("File2")
	if !reflect.DeepEqual(data, file2_data) || err != nil {
		t.Error("Fails to load correct contents of shared file!")
		return
	}
	data, err = u7.LoadFile("File2")
	if !reflect.DeepEqual(data, file2_data) || err != nil {
		t.Error("Fails to load correct contents of shared file!")
		return
	}
	data, err = u3.LoadFile("File2")
	if err == nil || data != nil {
		t.Error("Person not shared with has access to file!")
		return
	}
	data, err = u4.LoadFile("File2")
	if err == nil || data != nil {
		t.Error("Person not shared with has access to file!")
		return
	}
	data, err = u5.LoadFile("File2")
	if err == nil || data != nil {
		t.Error("Person not shared with has access to file!")
		return
	}

	err = u6.RevokeFile("File2","u7")
	if err != nil {
		t.Error("Failed to revoke access!")
		return
	}
	err = u2.AppendFile("File2", []byte("This should not work!!!!!!!!!!!!!!!!!!!"))
	if err == nil {
		t.Error("Revoked user should not append!")
		return
	}
	data, err = u6.LoadFile("File2")
	if !reflect.DeepEqual(data, file2_data) || err != nil {
		t.Error("User shouldn't append file after revoked!")
		return
	}

	File2_token, err = u6.ShareFile("File2", "u7")
	err = u7.ReceiveFile("File2", "u6", File2_token)
	if err != nil {
		t.Error("Should be able to share again after revoking! ")
	}

	data, err = u7.LoadFile("File2")
	if !reflect.DeepEqual(data, file2_data) || err != nil {
		t.Error("User can't access data!")
		return
	}

	File2_token, err = u7.ShareFile("File2", "u1")
	err = u1.ReceiveFile("File2", "u7", File2_token)
	if err != nil {
		t.Error("Should be able to share again after revoking! ")
	}

	file2_data = append(file2_data, []byte("Something random!")...)
	err = u1.AppendFile("File2", []byte("Something random!"))
	if err != nil {
		t.Error("Should be able to append again after revoking! ")
	}

	data, err = u7.LoadFile("File2")
	if !reflect.DeepEqual(data, file2_data) || err != nil {
		t.Error("User can't access data!")
		return
	}

	err = u6.RevokeFile("File2", "u4")
	if err == nil {
		t.Error("Revoking nonexistent user should return error!")
		return
	}

	token, err := u6.ShareFile("File2", "NOneexistent!!!")
	if err == nil || token != "" {
		t.Error("Sharing nonexistent user should return error!")
		return
	}


	final_map := userlib.DatastoreGetMap()
	for k, _ := range final_map {
		userlib.DatastoreSet(k,userlib.RandomBytes(10))
	}
	err = u1.AppendFile("File1", []byte("Something"))
	if err == nil {
		t.Error("Should show error!")
	}
	_, err = u1.ShareFile("File1", "u3")
	if err == nil {
		t.Error("Shouldn't share after tamper! ")
	}
	err = u6.RevokeFile("File2", "u7")
	if err == nil {
		t.Error("Shouldn't revoke after tamper!")
	}
	_, err = GetUser("u4","u4_password")
	if err == nil {
		t.Error("Should return error!")
		return
	}
	_, err = u1.LoadFile("File1")
	if err == nil {
		t.Error("Should return error!")
		return
	}

}

func TestMultiInstantiationReceive(t *testing.T) {
	clear()
	a, _ := InitUser("a","a")
	content := userlib.RandomBytes(54)
	a.StoreFile("File", content)
	b_1, _ := InitUser("b", "b")
	b_2, _ := GetUser("b", "b")
	token, _ := a.ShareFile("File", "b")
	_ = b_1.ReceiveFile("File", "a", token)
	data, err := b_2.LoadFile("File")
	if err != nil || data == nil {
		t.Error("Doesn't support multi instantiation!")
		return
	}
	if !reflect.DeepEqual(data, content) {
		t.Error("Doesn't support multi instantiation!")
		return
	}

	err = b_2.ReceiveFile("File", "a",token)
	if err == nil {
		t.Error("Should return error!")
	}

	data, err = b_1.LoadFile("File")
	if err != nil || data == nil {
		t.Error("Doesn't support multi instantiation!")
		return
	}
	if !reflect.DeepEqual(data, content) {
		t.Error("Doesn't support multi instantiation!")
		return
	}

	a.StoreFile("File2", []byte("EMpty"))
	err = a.RevokeFile("File2", "b")
	if err == nil {
		t.Error("Should report error!")
	}

	clear()
	a, _ = InitUser("a","a")
	content = userlib.RandomBytes(54)
	a.StoreFile("File", content)
	_, _ = InitUser("b", "b")
	token, _ = a.ShareFile("File", "b")
	c, _ := InitUser("c", "c")
	err = c.ReceiveFile("File", "a", token)
	if err == nil {
		t.Error("Should report error!")
	}
	_, err = c.LoadFile("File")
	if err == nil {
		t.Error("Should report error!")
	}

	clear()
	a, _ = InitUser("a","a")
	content = userlib.RandomBytes(54)
	a.StoreFile("File", content)
	b, _ := InitUser("b", "b")
	token, _ = a.ShareFile("File", "b")
	_, _ = a.ShareFile("File", "c")
	c, _ = InitUser("c", "b")
	err = c.ReceiveFile("File", "a",token)
	if err == nil {
		t.Error("Should report error!")
	}
	err = b.ReceiveFile("File", "a", token)
	if err != nil {
		t.Error("Should not report error!")
	}
	data, err = b.LoadFile("File")
	if !reflect.DeepEqual(data, content) {
		t.Error("Doesn't support multi instantiation!")
		return
	}
}

func TestReceiveFile2(t *testing.T){
	clear()
	u1, _ := InitUser("alice", "fubar")
	u2, _ := InitUser("bob", "barfu")
	u1.StoreFile("File1", []byte("content1"))
	token, _ := u1.ShareFile("File1", "bob")
	err := u2.ReceiveFile("File2", "alice", token)
	if err != nil {
		t.Error("Receive and rename failed")
		return
	}
	data1, _ := u1.LoadFile("File1")
	data2, _ := u2.LoadFile("File1")
	if reflect.DeepEqual(data1, data2) {
		t.Error("File should not be equal")
		return
	}
}

func TestManyInstanceAppend(t *testing.T) {
	clear()
	u1_1, _ := InitUser("alice", "fubar")
	u1_2, _ := GetUser("alice", "fubar")
	u1_3, _ := GetUser("alice", "fubar")
	u1_1.StoreFile("File1", []byte("content1"))
	_ = u1_2.AppendFile("File1", []byte("new2"))
	_ = u1_3.AppendFile("File1", []byte("new3"))
	v1, _ := u1_2.LoadFile("File1")
	v2, _ := u1_1.LoadFile("File1")
	if !reflect.DeepEqual(v1, v2) {
		t.Error("Version error")
		return
	}
	if reflect.DeepEqual(v2, []byte("content1")) {
		t.Error("Version error")
		return
	}

}

func TestRestoreTwice(t *testing.T) {
	clear()
	u1, _ := InitUser("alice", "fubar")
	u1.StoreFile("File1", []byte("content1"))
	u1.StoreFile("File1", []byte("content2"))
	v1, _ := u1.LoadFile("File1")
	if !reflect.DeepEqual(v1, []byte("content2")) {
		t.Error("Version error")
		return
	}
	
}

