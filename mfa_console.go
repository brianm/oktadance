package oktadance

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/chzyer/readline"
)

// NewConsoleMultifactor creates a `MultiFactor` which
// interacts with a user on the console to complete
// multifactor auth
//
// The exact console interface should be considered UNSTABLE.
// If you need a stable UI, you should implement `Multifactor` directly.
func NewConsoleMultifactor() (Multifactor, error) {
	l, err := readline.New("")
	if err != nil {
		return nil, err
	}
	return console{l}, nil
}

// Console handles the user input
type console struct {
	*readline.Instance
}

// Select the factor to use for the challenge
func (c console) Select(factors []Factor) (Factor, error) {
	for {
		fm := map[int]Factor{}
		options := []readline.PrefixCompleterInterface{}
		fs := []string{}
		fmt.Printf("select factor:\n")
		for i, f := range factors {
			options = append(options, readline.PcItem(f.FactorType()))
			fs = append(fs, strconv.Itoa(i))
			fm[i] = f
			fmt.Printf("  %d\t%s (%s)\n", i, f.FactorType(), f.Provider())
		}

		completer := readline.NewPrefixCompleter(options...)
		c.Config.AutoComplete = completer
		c.SetPrompt(fmt.Sprintf("factor [%s]: ", strings.Join(fs, ", ")))
		choice, err := c.Readline()
		if err != nil {
			return nil, err
		}
		choice = strings.TrimSpace(choice)
		idx, err := strconv.Atoi(choice)
		if err != nil {
			fmt.Printf("'%s' is not a valid choice\n", choice)
			continue
		}
		factor, ok := fm[idx]
		if ok {
			return factor, nil
		} else {
			fmt.Printf("%s is not an available factor\n", choice)
		}
	}

}

func (c console) ReadCode(Factor) (string, error) {
	c.SetPrompt("code: ")
	code, err := c.Readline()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(code), nil
}
