package main

import (
  "fmt"
  "os"
  "bufio"
  "strings"
)

func check(e error) {
  if e != nil {
    panic(e)
  }
}

func associateLines (s *[]string, index *int) *[]byte {
  var lines []byte

  current, last := 0, -1

  for current >= last {
    buffer := []byte((*s)[*index])
    for ; buffer[current] == ' '; current++ {}

    if current <= last && buffer[current] != '-' {
      (*index)--
      break
    }

    lines = append(lines, buffer...)

    (*index)++
    if *index >= len(*s) {
      break
    }

    last = current
  }

  return &lines
}

func fetchFieldName (s *string) (*string) {
  input := []byte(*s)
  start, end := 0, 0

  for ; input[end] != ':'; end++ {
    if input[end] == ' ' {
      start++;
    }

    if end >= len(*s) - 1  || input[end] == '#'{
      return nil
    }
  }

  name := string(input[start:end])
  return &name
}

func stripFieldName (lines *[]byte) (*string) {
  temp := string(*lines)
  name := fetchFieldName(&temp)

  temp = string((*lines)[strings.Index(string(*lines), *name) + len(*name) + 1:])

  return &temp
}

func writeFile (s *string, indent int) { //remove indent var or make global
  start := 0
  length := len(*s)

  for i := 0; i < length; i++ {

    if (*s)[i] == '\n' {

      for j := 0; j < indent * 2; j++ {
        outputFile.Write([]byte(" "))
      }

      outputFile.Write([]byte((*s)[start:i]))
      outputFile.Write([]byte("\n"))

      if i < length - 1 && (*s)[i + 1] != '-' {
        indent++
      }
      start = i + 1
    }
  }
}

func writeMatchResource(s ...string) (*string) {
  lines := "match:\nresources:\nkinds:\n"

  if len(s) <= 0 {
    lines += "- Pod\n"
  } else {
    for _, kinds := range s {
      lines += ("- " + kinds + "\n")
    }
  }

  return &lines
}

func writeList(s *string) (*string) {
  str := strings.Split(*s, "-")
  var ret string

  for _, i := range str {
    temp := strings.TrimLeft(i, " ")
    if temp != "" {
      ret += ("- " + temp + "\n")
    }
  }

  return &ret
}

func writeApiVersion (lines *[]byte) {
  str := "apiVersion: kyverno.io/v1\n"
  writeFile(&str, 0)
}

func writeKind (lines *[]byte) {
  str := "kind: ClusterPolicy\n"
  writeFile(&str, 0)
}

func writeMetadata (lines *[]byte) {
  str := "metadata:\n" + *stripFieldName(lines) + "\n"

  writeFile(&str, 0)
}

func writeSpec () {
  str := "spec:\nrules:\n"
  writeFile(&str, 0)
}

func writeAllowPrivilegeEscalation (lines *[]byte) {
  str := "- name: allowPrivilegeEscalation\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nallowPrivilegeEscalation:" + *stripFieldName(lines) + "\n"
  writeFile(&str, 2)
}

func writeAllowedCSIDrivers (lines *[]byte) {
  str := "- name: allowedCSIDrivers\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nvolumes:\ncsi:\ndriver:\n"
  writeFile(&str, 2)

  temp := []byte(*stripFieldName(lines))
  writeFile(writeList(stripFieldName(&temp)), 7)
}

func writeAllowedCapabilities (lines *[]byte) {
  str := "- name: allowedCapabilities\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\ncapabilities:\nadd:\n"
  writeFile(&str, 2)

  writeFile(writeList(stripFieldName(lines)), 7)
}

func writeAllowedFlexVolumes (lines *[]byte) {
  str := "- name: allowedFlexVolumes\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\nrules:\nvalidate:\npattern:\nspec:\nvolumes:\nflexVolume:\ndriver:"
  writeFile(&str, 2)

  temp := []byte(*stripFieldName(lines))
  writeFile(writeList(stripFieldName(&temp)), 8)
}

func writeAllowedHostPaths (lines *[]byte) {
  str := "- name: allowedHostPaths\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nvolumes:\nhostPath:\n"
  writeFile(&str, 2)

  //TODO
}

func writeAllowedProcMountTypes (lines *[]byte) {
  str := "- name: allowedProcMountTypes\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nprocMount:\n"
  writeFile(&str, 2)

  writeFile(writeList(stripFieldName(lines)), 6)
}

func writeAllowedUnsafeSysctls (lines *[]byte) {
  str := "- name: allowedUnsafeSysctls\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nsecurityContext:\nsysctls:\nvalue:\n"
  writeFile(&str, 2)

  writeFile(writeList(stripFieldName(lines)), 7)
}

func writeFsGroup (lines *[]byte) {
  str := "- name: fsGroup\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nsecurityContext:\nfsGroup:\n"
  writeFile(&str, 2)
}

func writeHostIPC (lines *[]byte) {
  str := "- name: hostIPC\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nhostIPC:" + *stripFieldName(lines) + "\n"
  writeFile(&str, 2)
}

func writeHostNetwork (lines *[]byte) {
  str := "- name: hostNetwork\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nhostNetwork:" + *stripFieldName(lines) + "\n"
  writeFile(&str, 2)
}

func writeHostPID (lines *[]byte) {
  str := "- name: hostPID\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nhostPID:" + *stripFieldName(lines) + "\n"
  writeFile(&str, 2)
}

func writeHostPorts (lines *[]byte) {
  str := "- name: hostPorts\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- ports:\n- hostPort:"
  writeFile(&str, 2)
}

func writePrivileged (lines *[]byte) {
  str := "- name: privileged\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nprivileged:" + *stripFieldName(lines) + "\n"
  writeFile(&str, 2)
}

func writeReadOnlyRootFilesystem (lines *[]byte) {
  str := "- name: readOnlyRootFilesystem\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nreadOnlyRootFilesystem:" + *stripFieldName(lines) + "\n"
  writeFile(&str, 2)
}

func writeRequiredDropCapabilities (lines *[]byte) {
  str := "- name: requiredDropCapabilities\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\ncapabilities:\ndrop:\n"
  writeFile(&str, 2)

  writeFile(writeList(stripFieldName(lines)), 7)
}

func writerRunAsGroup (lines *[]byte) {
  str := "- name: runAsGroup\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nrunAsGroup:"
  writeFile(&str, 2)
}

func writeRunAsUser (lines *[]byte) {
  str := "- name: runAsUser\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nrunAsUser:"
  writeFile(&str, 2)
}

func writeRuntimeClass (lines *[]byte) {
  str := "- name: runtimeClass\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nruntimeClassName:"
  writeFile(&str, 2)
}

func writeSeLinux (lines *[]byte) {
  str := "- name: seLinux\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\ncontainers:\n- securityContext:\nseLinuxOptions:"
  writeFile(&str, 2)
}

func writeSupplementalGroups (lines *[]byte) {
  str := "- name: supplementalGroups\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nsecurityContext:\nsupplementalGroups:\n"
  writeFile(&str, 2)
}

func writeVolumes (lines *[]byte) {
  str := "- name: volumes\n"
  writeFile(&str, 1)
  writeFile(writeMatchResource(), 2)

  str = "validate:\npattern:\nspec:\nvolumes:\n"
  writeFile(&str, 2)

  writeFile(writeList(stripFieldName(lines)), 5)
}



var outputFile, err = os.Create("test.yaml")
func main() {
  check(err)
  inputFile, err := os.Open("PSP.yaml")
  check(err)

  //writeFile, err := os.Create("test.yaml")

  sc := bufio.NewScanner(inputFile)
  var buffer []string

  for sc.Scan() {
    buffer = append(buffer, sc.Text())
  }

  for i := 0; i < len(buffer); i++ {
    var lines *[]byte

    name := fetchFieldName(&(buffer[i]))

    if name != nil {
      if *name != "spec" {
        lines = associateLines(&buffer, &i)
      }

      fmt.Println("Name:", string(*name))
      //fmt.Println("Lines:", string(*lines))

      switch *name {
        case "apiVersion": writeApiVersion(lines)
        case "kind": writeKind(lines)
        case "metadata": writeMetadata(lines)
        case "spec": writeSpec()
        case "allowPrivilegeEscalation": writeAllowPrivilegeEscalation(lines)
        case "allowedCSIDrivers": writeAllowedCSIDrivers(lines)
        case "allowedCapabilities": writeAllowedCapabilities(lines)
        case "allowedFlexVolumes": writeAllowedFlexVolumes(lines)
        // case "allowedHostPaths": writeAllowedHostPaths(lines)
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
