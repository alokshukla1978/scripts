@main def exec(spFilename: String, outFilename: String) = {
  loadSp(spFilename)
  sp.findings.sortedByScore.l |> outFilename
}
