module github.com/AiKeyLabs/pkg/scannode

go 1.26.1

require (
	github.com/AiKeyLabs/pkg/deepscan v0.0.0
	github.com/AiKeyLabs/pkg/seatassign v0.0.0
)

replace github.com/AiKeyLabs/pkg/deepscan => ../deepscan

replace github.com/AiKeyLabs/pkg/seatassign => ../seatassign
