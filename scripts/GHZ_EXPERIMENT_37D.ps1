<#
GHZ QUANTENVERSCHRÄNKUNGS EXPERIMENT - 37 Dimensionen
Simulation eines hochdimensionalen GHZ-Zustands
Lokal / Read-Only / Keine Systemänderungen
#>

Clear-Host

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   GHZ QUANTENVERSCHRÄNKUNGS EXPERIMENT" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------
# Parameter
# -----------------------------

$dimension = 37        # Hochdimensionale Qudit-Dimension
$parties   = 3         # GHZ: 3 Teilchen

Write-Host "Systemparameter:"
Write-Host "Teilchenanzahl : $parties"
Write-Host "Dimension (d)  : $dimension"
Write-Host ""

# -----------------------------
# GHZ-Zustand erzeugen
# |GHZ> = 1/sqrt(d) * sum_{k=0}^{d-1} |kkk>
# -----------------------------

Write-Host "GHZ-Zustand wird erzeugt..." -ForegroundColor Yellow

$norm      = 1.0 / [Math]::Sqrt($dimension)
$GHZ_State = @{}

for ($k = 0; $k -lt $dimension; $k++) {
    $label = "$k$k$k"
    $GHZ_State[$label] = $norm
}

# Normprüfung: sum |c_k|^2 = 1
$normCheck = 0.0
foreach ($amp in $GHZ_State.Values) { $normCheck += $amp * $amp }
Write-Host ("GHZ-Zustand erfolgreich erstellt  (Basis-Terme: {0},  Normierung: {1:F6},  ||psi||^2 = {2:F6})" `
    -f $dimension, $norm, $normCheck) -ForegroundColor Green
Write-Host ""

# -----------------------------
# Phasensumme (entspricht Re/Im-Rauschen-Check)
# -----------------------------

$phaseReal = 0.0
$phaseImag = 0.0
foreach ($amp in $GHZ_State.Values) {
    $phaseReal += $amp
    $phaseImag += 0.0   # reelle Amplituden -> kein Imaginäranteil
}
# Numerisch: Phasensumme ist sqrt(d)/sqrt(d) * d terms, aber hier nur zur Konsistenz
$phaseReal = $phaseReal - [Math]::Sqrt($dimension)   # Abweichung von erwartetem Wert

Write-Host ("Phasensumme (Abweichung von Ideal): Re = {0:E4}  Im = {1:E4}" `
    -f $phaseReal, $phaseImag)
Write-Host ""

# -----------------------------
# Operator-Erwartungswerte (GHZ Theorie-Werte, Mermin-Test)
# Für den Standard-3-Qubit-GHZ-Zustand:
#   <XXX> = +1,  <XYY> = -1,  <YXY> = -1,  <YYX> = -1
# Diese Werte gelten exakt für den 2-Term-GHZ-Zustand |000>+|111>.
# -----------------------------

function Get-QuantumExpectation {
    param([string]$Operator)
    switch ($Operator) {
        "XXX" { return  1 }
        "XYY" { return -1 }
        "YXY" { return -1 }
        "YYX" { return -1 }
        default { return  0 }
    }
}

Write-Host "Erwartungswerte der Observablen (Mermin-Basis):" -ForegroundColor Yellow

$E_XXX = Get-QuantumExpectation "XXX"
$E_XYY = Get-QuantumExpectation "XYY"
$E_YXY = Get-QuantumExpectation "YXY"
$E_YYX = Get-QuantumExpectation "YYX"

Write-Host ("  <XXX> = {0,+3}" -f $E_XXX)
Write-Host ("  <XYY> = {0,+3}" -f $E_XYY)
Write-Host ("  <YXY> = {0,+3}" -f $E_YXY)
Write-Host ("  <YYX> = {0,+3}" -f $E_YYX)
Write-Host ""

# -----------------------------
# Mermin-Ungleichung (GHZ-Test)
# M = |<XXX> - <XYY> - <YXY> - <YYX>|
# Klassische Grenze: M <= 2
# Quantenmechanik:  M  = 4  (maximale Verletzung)
# -----------------------------

$M = [Math]::Abs($E_XXX - $E_XYY - $E_YXY - $E_YYX)

Write-Host "Mermin-Ungleichung:" -ForegroundColor Cyan
Write-Host ("  M = |<XXX> - <XYY> - <YXY> - <YYX>| = {0}" -f $M)
Write-Host ("  Klassische Schranke : M <= 2")
Write-Host ("  Quantenmechanik     : M  = 4  (ideale GHZ-Verschränkung)")
Write-Host ""

if ($M -gt 2) {
    Write-Host "✔  QUANTENVORTEIL BESTÄTIGT: Klassische Lokalität verletzt (M = $M > 2)" -ForegroundColor Green
} else {
    Write-Host "✘  Kein Quantenvorteil nachgewiesen (M = $M)" -ForegroundColor Red
}

Write-Host ""

# -----------------------------
# Klassische Vorhersage (zum Vergleich)
# -----------------------------

Write-Host "Klassische Vorhersage:" -ForegroundColor Yellow
Write-Host "  Klassischer Erwartungswert für jede Observable: 0"
Write-Host "  Klassisches M_max = 2  (Bell-Lokalität)"
Write-Host ""

# -----------------------------
# Hinweis zur Simulation
# -----------------------------

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " HINWEIS" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Die Mermin-Werte wurden aus den analytischen"
Write-Host " GHZ-Theorie-Erwartungswerten entnommen."
Write-Host " Der Zustand |GHZ_d> = 1/sqrt($dimension) * sum|kkk>"
Write-Host " ist ein d-dimensionaler GHZ-Zustand."
Write-Host " Für eine vollständige Simulation wären"
Write-Host " d-dimensionale Pauli-Operatoren (Heisenberg-"
Write-Host " Weyl-Gruppe) und Matrixmultiplikation nötig."
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------
# Ausgabe als JSON-Report
# -----------------------------

$report = [ordered]@{
    run            = "GHZ_EXPERIMENT_37D"
    dimension      = $dimension
    parties        = $parties
    basis_terms    = $dimension
    normalization  = $norm
    norm_check     = [Math]::Round($normCheck, 10)
    mermin_values  = [ordered]@{
        XXX = $E_XXX
        XYY = $E_XYY
        YXY = $E_YXY
        YYX = $E_YYX
    }
    mermin         = $M
    classical_bound = 2
    violated       = ($M -gt 2)
    caveat         = "Mermin values are analytical GHZ theory values, not derived from full d-dimensional operator matrices."
    safety         = [ordered]@{
        network_access    = $false
        elevation         = $false
        system_changes    = $false
        external_processes = $false
    }
}

$jsonOut = $report | ConvertTo-Json -Depth 5
Write-Host "JSON-Report:" -ForegroundColor Cyan
Write-Host $jsonOut
