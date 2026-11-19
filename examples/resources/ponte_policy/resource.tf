resource "ponte_policy" "refund_guard" {
  ppl              = file("${path.module}/policies/refund-guard.yaml")
  enforcement_mode = "observe" # enforce once you have watched it
}
