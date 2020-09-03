package main

import (
  "fmt"
  "os"
  "bufio"
  "strings"
)

// check for file opening errors
func check(e error) {
  if e != nil {
    panic(e)
  }
}

// associate a field with its related lines
func associateLines (s *[]string, index *int) *[]byte {
  // variable to store all related lines
  var lines []byte

  // current is the amount of indent for the current line being read
  // last is the amount of indent for the last line
  current, last := 0, -1

  for current >= last {
    // buffer is equal to the line at index
    buffer := []byte((*s)[*index])
    // increase current for every space at the beginning of a line
    for ; buffer[current] == ' '; current++ {}

    // if current line is less indented than last or current line is a list item
    if current <= last && buffer[current] != '-' {
      (*index)--
      break
    }

    // append current line to []byte lines
    lines = append(lines, buffer...)

    (*index)++
    // increment index and if out of bounds break
    if *index >= len(*s) {
      break
    }

    // last number of indents is set to current number of indents
    last = current
  }

  // return []byte lines which contains all lines associated with a field
  // begins with field line
  return &lines
}

// returns field name without indents and colon
func fetchFieldName (s *string) (*string) {
  input := []byte(*s)

  // start is index of first letter of field and end is index of last letter
  start, end := 0, 0

  // loop through line until colon is found
  for ; input[end] != ':'; end++ {

    // increment start for every space found
    if input[end] == ' ' {
      start++;
    }

    // if no colon in line then return nil
    if end >= len(*s) - 1  || input[end] == '#'{
      return nil
    }
  }

  //copy field name into name and return address
  name := string(input[start:end])
  return &name
}

// removes field name from lines
// used to remove first field and return only succeeding data
func stripFieldName (lines *[]byte) (*string) { //TODO add multiple strip parameter
  temp := string(*lines)

  // save field name without preceding indents or terminating colon
  name := fetchFieldName(&temp)

  // remove substring name from lines including terminating colon
  temp = string((*lines)[strings.Index(string(*lines), *name) + len(*name) + 1:])

  return &temp
}

// used to write string to global outputFile, ensuring the correct indent
func writeFile (s *string, indent int) { //TODO remove indent var or make global
  // where to start writing from
  start := 0
  length := len(*s)

  // loop through string s
  // i is current position and is used to denote where to end writing
  for i := 0; i < length; i++ {

    // if newline is found
    if (*s)[i] == '\n' {

      // then begin the next line with given number of spaces as indent
      for j := 0; j < indent * 2; j++ {
        outputFile.Write([]byte(" "))
      }

      // and write the string from start position to currently found newline
      outputFile.Write([]byte((*s)[start:i]))
      outputFile.Write([]byte("\n"))

      // if next line is a list item or out of bounds then do not increment
      if i < length - 1 && (*s)[i + 1] != '-' {
        indent++
      }

      //start begins after last written char
      start = i + 1
    }
  }
}

// function to quickly return the common match/resources/kinds string
// ability to specify many or no kinds
func writeMatchResource(s ...string) (*string) {
  // default string, indents automatically applied in writeFile
  lines := "match:\nresources:\nkinds:\n"

  // if no parameters are passed
  if len(s) <= 0 {
    // add Pod by default
    lines += "- Pod\n"
  } else {
    // else add all parameters that are passed as a new list item
    for _, kinds := range s {
      lines += ("- " + kinds + "\n")
    }
  }

  return &lines
}

// utility to reformat list items read from inputFile
func writeList(s *string) (*string) {
  // tokenize s at "-"
  str := strings.Split(*s, "-")
  var ret string

  // loop through tokens
  for _, i := range str {
    // remove leading whitespace
    temp := strings.TrimLeft(i, " ")

    // if string is not empty
    if temp != "" {
      // add list item to ret
      // formatted in a way that writeFile can apply correct indentation
      ret += ("- " + temp + "\n")
    }
  }

  return &ret
}

// write the Kyverno equivalent of apiVersion
func writeApiVersion (lines *[]byte) {
  str := "apiVersion: kyverno.io/v1\n"
  // write str to outputFile with 0 indentation
  writeFile(&str, 0)
}

// write the Kyverno equivalent of kind
func writeKind (lines *[]byte) {
  str := "kind: ClusterPolicy\n"
  writeFile(&str, 0)
}

// write the Kyverno equivalent of metadata
func writeMetadata (lines *[]byte) {
  // str is "metadata" followed by whatever data was associated with inputFile metadata
  // lines contains original field name, so it must be removed so only the data remains
  str := "metadata:\n" + *stripFieldName(lines) + "\n"

  writeFile(&str, 0)
}

// write the Kyverno equivalent of spec
func writeSpec () {
  str := "spec:\nrules:\n"
  writeFile(&str, 0)
}

// write the Kyverno equivalent of allowPrivilegeEscalation
func writeAllowPrivilegeEscalation (lines *[]byte) {
  // Kyverno equivalent begins with - name:
  str := "- name: allowPrivilegeEscalation\n"
  writeFile(&str, 1)

  // match/resource/kinds block is written
  writeFile(writeMatchResource(), 2)

  // Kyverno equivalent of allowPrivilegeEscalation followed by the original data
  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nallowPrivilegeEscalation:" + *stripFieldName(lines) + "\n"
  writeFile(&str, 2)
}

// write the Kyverno equivalent of allowedCSIDrivers
func writeAllowedCSIDrivers (lines *[]byte) {
  //Kyverno equivalent beings with - name:
  str := "- name: allowedCSIDrivers\n"
  writeFile(&str, 1)

  //write match/resource/kinds block
  writeFile(writeMatchResource(), 2)

  // Kyverno equivalent of allowedCSIDrivers is written
  str = "validate:\npattern:\nspec:\nvolumes:\ncsi:\ndriver:\n"
  writeFile(&str, 2)

  // lines needes stripped twice
  temp := []byte(*stripFieldName(lines))
  //write stripped data to file
  writeFile(writeList(stripFieldName(&temp)), 7)
}

// write the Kyverno equivalent of allowedCapabilities
func writeAllowedCapabilities (lines *[]byte) {
  str := "- name: allowedCapabilities\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\ncapabilities:\nadd:\n"
  writeFile(&str, 2)

  writeFile(writeList(stripFieldName(lines)), 7)
}

// write the Kyverno equivalent of allowedFlexVolumes
func writeAllowedFlexVolumes (lines *[]byte) {
  str := "- name: allowedFlexVolumes\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\nrules:\nvalidate:\npattern:\nspec:\nvolumes:\nflexVolume:\ndriver:"
  writeFile(&str, 2)

  temp := []byte(*stripFieldName(lines))
  writeFile(writeList(stripFieldName(&temp)), 8)
}

// write the Kyverno equivalent of allowedHostPaths
func writeAllowedHostPaths (lines *[]byte) {
  str := "- name: allowedHostPaths\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nvolumes:\nhostPath:\n"
  writeFile(&str, 2)

  //TODO
}

// write the Kyverno equivalent of allowedProcMountTypes
func writeAllowedProcMountTypes (lines *[]byte) {
  str := "- name: allowedProcMountTypes\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nprocMount:\n"
  writeFile(&str, 2)

  writeFile(writeList(stripFieldName(lines)), 6)
}

// write the Kyverno equivalent of allowedUnsafeSysctls
func writeAllowedUnsafeSysctls (lines *[]byte) {
  str := "- name: allowedUnsafeSysctls\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nsecurityContext:\nsysctls:\nvalue:\n"
  writeFile(&str, 2)

  writeFile(writeList(stripFieldName(lines)), 7)
}

// write the Kyverno equivalent of fsGroup
func writeFsGroup (lines *[]byte) {
  str := "- name: fsGroup\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nsecurityContext:\nfsGroup:\n"
  writeFile(&str, 2)
}

// write the Kyverno equivalent of hostIPC
func writeHostIPC (lines *[]byte) {
  str := "- name: hostIPC\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nhostIPC:" + *stripFieldName(lines) + "\n"
  writeFile(&str, 2)
}

// write the Kyverno equivalent of hostNetwork
func writeHostNetwork (lines *[]byte) {
  str := "- name: hostNetwork\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nhostNetwork:" + *stripFieldName(lines) + "\n"
  writeFile(&str, 2)
}

// write the Kyverno equivalent of hostPID
func writeHostPID (lines *[]byte) {
  str := "- name: hostPID\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nhostPID:" + *stripFieldName(lines) + "\n"
  writeFile(&str, 2)
}

// write the Kyverno equivalent of hostPorts
func writeHostPorts (lines *[]byte) {
  str := "- name: hostPorts\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- ports:\n- hostPort:"
  writeFile(&str, 2)
}

// write the Kyverno equivalent of privileged
func writePrivileged (lines *[]byte) {
  str := "- name: privileged\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nprivileged:" + *stripFieldName(lines) + "\n"
  writeFile(&str, 2)
}

// write the Kyverno equivalent of readOnlyRootFilesystem
func writeReadOnlyRootFilesystem (lines *[]byte) {
  str := "- name: readOnlyRootFilesystem\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nreadOnlyRootFilesystem:" + *stripFieldName(lines) + "\n"
  writeFile(&str, 2)
}

// write the Kyverno equivalent of requiredDropCapabilities
func writeRequiredDropCapabilities (lines *[]byte) {
  str := "- name: requiredDropCapabilities\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\ncapabilities:\ndrop:\n"
  writeFile(&str, 2)

  writeFile(writeList(stripFieldName(lines)), 7)
}

// write the Kyverno equivalent of runAsGroup
func writerRunAsGroup (lines *[]byte) {
  str := "- name: runAsGroup\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nrunAsGroup:"
  writeFile(&str, 2)
}

// write the Kyverno equivalent of runAsUser
func writeRunAsUser (lines *[]byte) {
  str := "- name: runAsUser\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nrunAsUser:"
  writeFile(&str, 2)
}

// write the Kyverno equivalent of runtimeClass
func writeRuntimeClass (lines *[]byte) {
  str := "- name: runtimeClass\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nruntimeClassName:"
  writeFile(&str, 2)
}

// write the Kyverno equivalent of seLinux
func writeSeLinux (lines *[]byte) {
  str := "- name: seLinux\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nseLinuxOptions:"
  writeFile(&str, 2)
}

// write the Kyverno equivalent of supplementalGroups
func writeSupplementalGroups (lines *[]byte) {
  str := "- name: supplementalGroups\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nsecurityContext:\nsupplementalGroups:\n"
  writeFile(&str, 2)
}

// write the Kyverno equivalent of volumes
func writeVolumes (lines *[]byte) {
  str := "- name: volumes\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nvolumes:\n"
  writeFile(&str, 2)

  writeFile(writeList(stripFieldName(lines)), 5)
}


// global outFile for writeFile to use
//TODO fix this so only writeFile can use
var outputFile, err = os.Create("test.yaml")

func main() {
  // check outputFile err for errors
  check(err)

  // open inputFile to read from
  inputFile, err := os.Open("PSP.yaml")
  check(err)

  // create scanner on inputFile
  sc := bufio.NewScanner(inputFile)
  var buffer []string

  // scan input file line by line and append each line to []string
  for sc.Scan() {
    buffer = append(buffer, sc.Text())
  }

  // loop through []string buffer
  // each index contains a line from inputFile
  for i := 0; i < len(buffer); i++ {
    var lines *[]byte

    // isolate yaml field names on given line
    name := fetchFieldName(&(buffer[i]))

    // if field name was found e.g. not a comment or list item
    if name != nil {

      // spec field of PSP contains other fields, so it much be discarded
      // if field is not "spec"
      if *name != "spec" {
        // then grab field data e.g. subfields, list items
        lines = associateLines(&buffer, &i)
      }

      // print name of field being read
      fmt.Println("Name:", string(*name))

      // use field name to send lines to specific funtion to convert PSP to Kyverno
      // commented out cases have incomplete mapping
      // most are situations where multiple values can exist in PSP but only a single value is present in Kyverno
      switch *name {
        case "apiVersion": writeApiVersion(lines)
        case "kind": writeKind(lines)
        case "metadata": writeMetadata(lines)
        case "spec": writeSpec()
        case "allowPrivilegeEscalation": writeAllowPrivilegeEscalation(lines)
        case "allowedCSIDrivers": writeAllowedCSIDrivers(lines)
        case "allowedCapabilities": writeAllowedCapabilities(lines)
        case "allowedFlexVolumes": writeAllowedFlexVolumes(lines)
        //case "allowedHostPaths": writeAllowedHostPaths(lines)
        case "allowedProcMountTypes": writeAllowedProcMountTypes(lines)
        case "allowedUnsafeSysctls": writeAllowedUnsafeSysctls(lines)
        //case "defaultAddCapabilities": writeDefaultAddCapabilities(lines)
        //case "defaultAllowPrivilegeEscalation": writeDefaultAllowPrivilegeEscalation(lines)
        //case "forbiddenSysctls": writeForbiddenSysctls(lines)
        //case "fsGroup": writeFsGroup(lines)
        case "hostIPC": writeHostIPC(lines)
        case "hostNetwork": writeHostNetwork(lines)
        case "hostPID": writeHostPID(lines)
        //case "hostPorts": writeHostPorts(lines)
        case "privileged": writePrivileged(lines)
        case "readOnlyRootFilesystem": writeReadOnlyRootFilesystem(lines)
        case "requiredDropCapabilities": writeRequiredDropCapabilities(lines)
        //case "runAsGroup": writerRunAsGroup(lines)
        //case "runAsUser": writeRunAsUser(lines)
        //case "runtimeClass": writeRuntimeClass(lines)
        //case "seLinux": writeSeLinux(lines)
        //case "supplementalGroups": writeSupplementalGroups(lines)
        case "volumes": writeVolumes(lines)
      }
    }
  }

  inputFile.Close()
  outputFile.Close()
}
