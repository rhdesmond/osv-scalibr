// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package etcshadow

import (
	"errors"
	"strings"

	"github.com/gehirninc/crypt/sha512_crypt"
	"golang.org/x/crypto/bcrypt"
)

// Error returned when a cracker did not find a matching password.
var ErrNotCracked = errors.New("not cracked")

type Cracker interface {
	// Crack() returns (password,nil) on success and ("", ErrNotCracked) on failure.
	Crack(string) (string, error)
}

type passwordCracker struct {
	bcryptCracker     Cracker
	sha12cryptCracker Cracker
}

// Returns a cracker that can attempt to find the password for a given hash.
func NewPasswordCracker() *passwordCracker {
	return &passwordCracker{
		bcryptCracker:     bcryptCracker{},
		sha12cryptCracker: sha512CryptCracker{},
	}
}

func (c passwordCracker) Crack(hash string) (password string, err error) {
	password, err = "", ErrNotCracked
	switch {
	case strings.HasPrefix(hash, "$2"):
		password, err = c.bcryptCracker.Crack(hash)
	case strings.HasPrefix(hash, "$6"):
		password, err = c.sha12cryptCracker.Crack(hash)
	}
	return
}

// Cracker for bcrypt password hashes.
type bcryptCracker struct {
}

func (c bcryptCracker) Crack(hash string) (string, error) {
	for _, v := range top100Passwords {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(v))
		if err == nil {
			return v, nil
		}
	}
	return "", ErrNotCracked
}

// Cracker for sha512crypt password hashes.
type sha512CryptCracker struct {
}

func (c sha512CryptCracker) Crack(hash string) (string, error) {
	crypter := sha512_crypt.New()
	for _, v := range top100Passwords {
		err := crypter.Verify(hash, []byte(v))
		if err == nil {
			return v, nil
		}
	}
	return "", ErrNotCracked
}

// This list of passwords is identical to the one used by the Tsunami plug-in
// for weak credentials detection. It comes originally from:
// https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt
var top100Passwords = []string{
	"",
	"root",
	"test",
	"123456",
	"password",
	"Password",
	"12345678",
	"qwerty",
	"123456789",
	"12345",
	"1234",
	"111111",
	"1234567",
	"dragon",
	"123123",
	"baseball",
	"abc123",
	"football",
	"monkey",
	"letmein",
	"696969",
	"shadow",
	"master",
	"666666",
	"qwertyuiop",
	"123321",
	"mustang",
	"1234567890",
	"michael",
	"654321",
	"pussy",
	"superman",
	"1qaz2wsx",
	"7777777",
	"fuckyou",
	"121212",
	"000000",
	"qazwsx",
	"123qwe",
	"killer",
	"trustno1",
	"jordan",
	"jennifer",
	"zxcvbnm",
	"asdfgh",
	"hunter",
	"buster",
	"soccer",
	"harley",
	"batman",
	"andrew",
	"tigger",
	"sunshine",
	"iloveyou",
	"fuckme",
	"2000",
	"charlie",
	"robert",
	"thomas",
	"hockey",
	"ranger",
	"daniel",
	"starwars",
	"klaster",
	"112233",
	"george",
	"asshole",
	"computer",
	"michelle",
	"jessica",
	"pepper",
	"1111",
	"zxcvbn",
	"555555",
	"11111111",
	"131313",
	"freedom",
	"777777",
	"pass",
	"fuck",
	"maggie",
	"159753",
	"aaaaaa",
	"ginger",
	"princess",
	"joshua",
	"cheese",
	"amanda",
	"summer",
	"love",
	"ashley",
	"6969",
	"nicole",
	"chelsea",
	"biteme",
	"matthew",
	"access",
	"yankees",
	"987654321",
	"dallas",
	"austin",
	"thunder",
	"taylor",
	"matrix",
	"Password123", // used by unit tests.
}
