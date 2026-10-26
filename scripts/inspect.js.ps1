$path = 'c:/Users/Aliah/OneDrive/Desktop/my stuff/personal projects/vulnerability scanner/frontend/src/App.js'
$lines = [System.IO.File]::ReadAllLines($path)
for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -match 'Fuzzer status poll failed|const toggleFuzzTest') {
        Write-Output ("{0}: {1}" -f ($i + 1), $lines[$i].Trim())
    }
}
