<?php
/*
 * This document has been generated with
 * https://mlocati.github.io/php-cs-fixer-configurator/#version:3.70.0|configurator
 * you can change this configuration by importing this file.
 */
return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setRules([
        // Each line of multi-line DocComments must have an asterisk [PSR-5] and must be aligned with the first one.
        'align_multiline_comment' => ['comment_type' => 'all_multiline'],
        // Each element of an array must be indented exactly once.
        'array_indentation' => true,
        // Converts simple usages of `array_push($x, $y);` to `$x[] = $y;`.
        'array_push' => true,
        // PHP arrays should be declared using the configured syntax.
        'array_syntax' => ['syntax' => 'short'],
        // Binary operators should be surrounded by space as configured.
        'binary_operator_spaces' => true,
        // There MUST be one blank line after the namespace declaration.
        'blank_line_after_namespace' => true,
        // Ensure there is no code on the same line as the PHP open tag and it is followed by a blank line.
        'blank_line_after_opening_tag' => true,
        // An empty line feed must precede any configured statement.
        'blank_line_before_statement' => ['statements' => ['return']],
        // Putting blank lines between `use` statement groups.
        'blank_line_between_import_groups' => true,
        // Controls blank lines before a namespace declaration.
        'blank_lines_before_namespace' => true,
        // Braces must be placed as configured.
        'braces_position' => true,
        // A single space or none should be between cast and variable.
        'cast_spaces' => true,
        // Class, trait and interface elements must be separated with one or none blank line.
        'class_attributes_separation' => true,
        // Whitespace around the keywords of a class, trait, enum or interfaces definition should be one space.
        'class_definition' => ['single_line' => true],
        // When referencing an internal class it must be written using the correct casing.
        'class_reference_name_casing' => true,
        // Namespace must not contain spacing, comments or PHPDoc.
        'clean_namespace' => true,
        // Using `isset($var) &&` multiple times should be done in one call.
        'combine_consecutive_issets' => true,
        // Calling `unset` on multiple items should be done in one call.
        'combine_consecutive_unsets' => true,
        // Replace multiple nested calls of `dirname` by only one call with second `$level` parameter.
        'combine_nested_dirname' => true,
        // Comments with annotation should be docblock when used on structural elements.
        'comment_to_phpdoc' => true,
        // Remove extra spaces in a nullable type declaration.
        'compact_nullable_type_declaration' => true,
        // Concatenation should be spaced according to configuration.
        'concat_space' => ['spacing' => 'one'],
        // The PHP constants `true`, `false`, and `null` MUST be written using the correct casing.
        'constant_case' => true,
        // The body of each control structure MUST be enclosed within braces.
        'control_structure_braces' => true,
        // Control structure continuation keyword must be on the configured line.
        'control_structure_continuation_position' => true,
        // The first argument of `DateTime::createFromFormat` method must start with `!`.
        'date_time_create_from_format_call' => true,
        // Equal sign in declare statement should be surrounded by spaces or not following configuration.
        'declare_equal_normalize' => true,
        // There must not be spaces around `declare` statement parentheses.
        'declare_parentheses' => true,
        // Force strict types declaration in all files.
        'declare_strict_types' => true,
        // Replaces `dirname(__FILE__)` expression with equivalent `__DIR__` constant.
        'dir_constant' => true,
        // Replaces short-echo `<?=` with long format `<?php echo`/`<?php print` syntax, or vice-versa.
        'echo_tag_syntax' => ['format' => 'short'],
        // The keyword `elseif` should be used instead of `else if` so that all control keywords look like single words.
        'elseif' => true,
        // Empty loop-body must be in configured style.
        'empty_loop_body' => ['style' => 'braces'],
        // Empty loop-condition must be in configured style.
        'empty_loop_condition' => ['style' => 'while'],
        // PHP code MUST use only UTF-8 without BOM (remove BOM).
        'encoding' => true,
        // Replace deprecated `ereg` regular expression functions with `preg`.
        'ereg_to_preg' => true,
        // Add curly braces to indirect variables to make them clear to understand.
        'explicit_indirect_variable' => true,
        // Converts implicit variables into explicit ones in double-quoted strings or heredoc syntax.
        'explicit_string_variable' => true,
        // PHP code must use the long `<?php` tags or short-echo `<?=` tags and not other tag variations.
        'full_opening_tag' => true,
        // Removes the leading part of fully qualified symbol references if a given symbol is imported or belongs to the current namespace.
        'fully_qualified_strict_types' => ['import_symbols' => true, 'leading_backslash_in_global_namespace' => false, 'phpdoc_tags' => []],
        // Spaces should be properly placed in a function declaration.
        'function_declaration' => true,
        // Replace core functions calls returning constants with the constants.
        'function_to_constant' => true,
        // Replace `get_class` calls on object variables with class keyword syntax.
        'get_class_to_class_keyword' => true,
        // Convert `heredoc` to `nowdoc` where possible.
        'heredoc_to_nowdoc' => true,
        // Function `implode` must be called with 2 arguments in the documented order.
        'implode_call' => true,
        // Include/Require and file path should be divided with a single space. File path should not be placed within parentheses.
        'include' => true,
        // Pre- or post-increment and decrement operators should be used if possible.
        'increment_style' => ['style' => 'post'],
        // Code MUST use configured indentation type.
        'indentation_type' => true,
        // Integer literals must be in correct case.
        'integer_literal_case' => true,
        // Replaces `is_null($var)` expression with `null === $var`.
        'is_null' => true,
        // Lambda must not import variables it doesn't use.
        'lambda_not_used_import' => true,
        // All PHP files must use same line ending.
        'line_ending' => true,
        // Ensure there is no code on the same line as the PHP open tag.
        'linebreak_after_opening_tag' => true,
        // List (`array` destructuring) assignment should be declared using the configured syntax.
        'list_syntax' => ['syntax' => 'short'],
        // Use `&&` and `||` logical operators instead of `and` and `or`.
        'logical_operators' => true,
        // Shorthand notation for operators should be used if possible.
        'long_to_shorthand_operator' => true,
        // Cast should be written in lower case.
        'lowercase_cast' => true,
        // PHP keywords MUST be in lower case.
        'lowercase_keywords' => true,
        // Class static references `self`, `static` and `parent` MUST be in lower case.
        'lowercase_static_reference' => true,
        // Magic constants should be referred to using the correct casing.
        'magic_constant_casing' => true,
        // Magic method definitions and calls must be using the correct casing.
        'magic_method_casing' => true,
        // In method arguments and method call, there MUST NOT be a space before each comma and there MUST be one space after each comma. Argument lists MAY be split across multiple lines, where each subsequent line is indented once. When doing so, the first item in the list MUST be on the next line, and there MUST be only one argument per line.
        'method_argument_space' => true,
        // Method chaining MUST be properly indented. Method chaining with different levels of indentation is not supported.
        'method_chaining_indentation' => true,
        // Replaces `intval`, `floatval`, `doubleval`, `strval` and `boolval` function calls with according type casting operator.
        'modernize_types_casting' => true,
        // DocBlocks must start with two asterisks, multiline comments must start with a single asterisk, after the opening slash. Both must end with a single asterisk before the closing slash.
        'multiline_comment_opening_closing' => true,
        // Convert multiline string to `heredoc` or `nowdoc`.
        'multiline_string_to_heredoc' => true,
        // Forbid multi-line whitespace before the closing semicolon or move the semicolon to the new line for chained calls.
        'multiline_whitespace_before_semicolons' => ['strategy' => 'new_line_for_chained_calls'],
        // Function defined by PHP should be called using the correct casing.
        'native_function_casing' => true,
        // Native type declarations should be used in the correct case.
        'native_type_declaration_casing' => true,
        // All instances created with `new` keyword must (not) be followed by parentheses.
        'new_with_parentheses' => true,
        // Master functions shall be used instead of aliases.
        'no_alias_functions' => true,
        // Master language constructs shall be used instead of aliases.
        'no_alias_language_construct_call' => true,
        // Replace control structure alternative syntax to use braces.
        'no_alternative_syntax' => true,
        // There should not be a binary flag before strings.
        'no_binary_string' => true,
        // There should be no empty lines after class opening brace.
        'no_blank_lines_after_class_opening' => true,
        // There should not be blank lines between docblock and the documented element.
        'no_blank_lines_after_phpdoc' => true,
        // There must be a comment when fall-through is intentional in a non-empty case body.
        'no_break_comment' => true,
        // The closing `? >` tag MUST be omitted from files containing only PHP.
        'no_closing_tag' => true,
        // There should not be any empty comments.
        'no_empty_comment' => true,
        // There should not be empty PHPDoc blocks.
        'no_empty_phpdoc' => true,
        // Remove useless (semicolon) statements.
        'no_empty_statement' => true,
        // Removes extra blank lines and/or blank lines following configuration.
        'no_extra_blank_lines' => ['tokens' => ['break','continue','curly_brace_block','extra','parenthesis_brace_block','return','square_brace_block','throw','use']],
        // Replace accidental usage of homoglyphs (non ascii characters) in names.
        'no_homoglyph_names' => true,
        // Remove leading slashes in `use` clauses.
        'no_leading_import_slash' => true,
        // The namespace declaration line shouldn't contain leading whitespace.
        'no_leading_namespace_whitespace' => true,
        // Either language construct `print` or `echo` should be used.
        'no_mixed_echo_print' => ['use' => 'echo'],
        // Operator `=>` should not be surrounded by multi-line whitespaces.
        'no_multiline_whitespace_around_double_arrow' => true,
        // There must not be more than one statement per line.
        'no_multiple_statements_per_line' => true,
        // Properties MUST not be explicitly initialized with `null` except when they have a type declaration (PHP 7.4).
        'no_null_property_initialization' => true,
        // Convert PHP4-style constructors to `__construct`.
        'no_php4_constructor' => true,
        // Short cast `bool` using double exclamation mark should not be used.
        'no_short_bool_cast' => true,
        // Single-line whitespace before closing semicolon are prohibited.
        'no_singleline_whitespace_before_semicolons' => true,
        // There must be no space around double colons (also called Scope Resolution Operator or Paamayim Nekudotayim).
        'no_space_around_double_colon' => true,
        // When making a method or function call, there MUST NOT be a space between the method or function name and the opening parenthesis.
        'no_spaces_after_function_name' => true,
        // There MUST NOT be spaces around offset braces.
        'no_spaces_around_offset' => true,
        // Replaces superfluous `elseif` with `if`.
        'no_superfluous_elseif' => true,
        // Removes `@param`, `@return` and `@var` tags that don't provide any useful information.
        'no_superfluous_phpdoc_tags' => true,
        // If a list of values separated by a comma is contained on a single line, then the last item MUST NOT have a trailing comma.
        'no_trailing_comma_in_singleline' => true,
        // Remove trailing whitespace at the end of non-blank lines.
        'no_trailing_whitespace' => true,
        // There MUST be no trailing spaces inside comment or PHPDoc.
        'no_trailing_whitespace_in_comment' => true,
        // Removes unneeded braces that are superfluous and aren't part of a control structure's body.
        'no_unneeded_braces' => true,
        // Removes unneeded parentheses around control statements.
        'no_unneeded_control_parentheses' => true,
        // Removes `final` from methods where possible.
        'no_unneeded_final_method' => true,
        // Imports should not be aliased as the same name.
        'no_unneeded_import_alias' => true,
        // In function arguments there must not be arguments with default values before non-default ones.
        'no_unreachable_default_argument_value' => true,
        // Variables must be set `null` instead of using `(unset)` casting.
        'no_unset_cast' => true,
        // Unused `use` statements must be removed.
        'no_unused_imports' => true,
        // There should not be useless concat operations.
        'no_useless_concat_operator' => true,
        // There should not be useless `else` cases.
        'no_useless_else' => true,
        // There should not be useless Null-safe operator `?->` used.
        'no_useless_nullsafe_operator' => true,
        // There should not be an empty `return` statement at the end of a function.
        'no_useless_return' => true,
        // There must be no `sprintf` calls with only the first argument.
        'no_useless_sprintf' => true,
        // In array declaration, there MUST NOT be a whitespace before each comma.
        'no_whitespace_before_comma_in_array' => true,
        // Remove trailing whitespace at the end of blank lines.
        'no_whitespace_in_blank_line' => true,
        // Remove Zero-width space (ZWSP), Non-breaking space (NBSP) and other invisible unicode symbols.
        'non_printable_character' => ['use_escape_sequences_in_strings' => true],
        // Array index should always be written by using square braces.
        'normalize_index_brace' => true,
        // Nullable single type declaration should be standardised using configured syntax.
        'nullable_type_declaration' => ['syntax' => 'question_mark'],
        // Adds or removes `?` before single type declarations or `|null` at the end of union types when parameters have a default `null` value.
        'nullable_type_declaration_for_default_null_value' => true,
        // There should not be space before or after object operators `->` and `?->`.
        'object_operator_without_whitespace' => true,
        // Operators - when multiline - must always be at the beginning or at the end of the line.
        'operator_linebreak' => true,
        // Orders the elements of classes/interfaces/traits/enums.
        'ordered_class_elements' => true,
        // Ordering `use` statements.
        'ordered_imports' => true,
        // PHPDoc should contain `@param` for all params.
        'phpdoc_add_missing_param_annotation' => true,
        // All items of the given PHPDoc tags must be either left-aligned or (by default) aligned vertically.
        'phpdoc_align' => ['align' => 'left'],
        // PHPDoc annotation descriptions should not be a sentence.
        'phpdoc_annotation_without_dot' => true,
        // Docblocks should have the same indentation as the documented subject.
        'phpdoc_indent' => true,
        // Changes doc blocks from single to multi line, or reversed. Works for class constants, properties and methods only.
        'phpdoc_line_span' => true,
        // `@access` annotations must be removed from PHPDoc.
        'phpdoc_no_access' => true,
        // No alias PHPDoc tags should be used.
        'phpdoc_no_alias_tag' => true,
        // Classy that does not inherit must not have `@inheritdoc` tags.
        'phpdoc_no_useless_inheritdoc' => true,
        // Annotations in PHPDoc should be ordered in defined sequence.
        'phpdoc_order' => true,
        // Orders all `@param` annotations in DocBlocks according to method signature.
        'phpdoc_param_order' => true,
        // The type of `@return` annotations of methods returning a reference to itself must the configured one.
        'phpdoc_return_self_reference' => true,
        // Scalar types should always be written in the same form. `int` not `integer`, `bool` not `boolean`, `float` not `real` or `double`.
        'phpdoc_scalar' => true,
        // Annotations in PHPDoc should be grouped together so that annotations of the same type immediately follow each other. Annotations of a different type are separated by a single blank line.
        'phpdoc_separation' => true,
        // Single line `@var` PHPDoc should have proper spacing.
        'phpdoc_single_line_var_spacing' => true,
        // PHPDoc summary should end in either a full stop, exclamation mark, or question mark.
        'phpdoc_summary' => true,
        // Fixes casing of PHPDoc tags.
        'phpdoc_tag_casing' => ['tags' => ['inheritdoc']],
        // Forces PHPDoc tags to be either regular annotations or inline.
        'phpdoc_tag_type' => ['tags' => ['inheritdoc' => 'inline']],
        // Docblocks should only be used on structural elements.
        'phpdoc_to_comment' => true,
        // PHPDoc should start and end with content, excluding the very first and last line of the docblocks.
        'phpdoc_trim' => true,
        // Removes extra blank lines after summary and after description in PHPDoc.
        'phpdoc_trim_consecutive_blank_line_separation' => true,
        // The correct case must be used for standard PHP types in PHPDoc.
        'phpdoc_types' => true,
        // Sorts PHPDoc types.
        'phpdoc_types_order' => ['null_adjustment' => 'always_last','sort_algorithm' => 'none'],
        // `@var` and `@type` annotations must have type and name in the correct order.
        'phpdoc_var_annotation_correct_order' => true,
        // `@var` and `@type` annotations of classy properties should not contain the name.
        'phpdoc_var_without_name' => true,
        // Converts `pow` to the `**` operator.
        'pow_to_exponentiation' => true,
        // Classes must be in a path that matches their namespace, be at least one namespace deep and the class name should match the file name.
        'psr_autoloading' => true,
        // Replaces `rand`, `srand`, `getrandmax` functions calls with their `mt_*` analogs or `random_int`.
        'random_api_migration' => true,
        // Local, dynamic and directly referenced variables should not be assigned and directly returned by a function or method.
        'return_assignment' => true,
        // Adjust spacing around colon in return type declarations and backed enum types.
        'return_type_declaration' => true,
        // Inside class or interface element `self` should be preferred to the class name itself.
        'self_accessor' => true,
        // Instructions must be terminated with a semicolon.
        'semicolon_after_instruction' => true,
        // Cast shall be used, not `settype`.
        'set_type_to_cast' => true,
        // Cast `(boolean)` and `(integer)` should be written as `(bool)` and `(int)`, `(double)` and `(real)` as `(float)`, `(binary)` as `(string)`.
        'short_scalar_cast' => true,
        // Converts explicit variables in double-quoted strings and heredoc syntax from simple to complex format (`${` to `{$`).
        'simple_to_complex_string_variable' => true,
        // Simplify `if` control structures that return the boolean result of their condition.
        'simplified_if_return' => true,
        // A PHP file without end tag must always end with a single empty line feed.
        'single_blank_line_at_eof' => true,
        // There MUST NOT be more than one property or constant declared per statement.
        'single_class_element_per_statement' => true,
        // There MUST be one use keyword per declaration.
        'single_import_per_statement' => true,
        // Each namespace use MUST go on its own line and there MUST be one blank line after the use statements block.
        'single_line_after_imports' => true,
        // Single-line comments must have proper spacing.
        'single_line_comment_spacing' => true,
        // Single-line comments and multi-line comments with only one line of actual content should use the `//` syntax.
        'single_line_comment_style' => true,
        // Convert double quotes to single quotes for simple strings.
        'single_quote' => true,
        // Ensures a single space after language constructs.
        'single_space_around_construct' => true,
        // Each trait `use` must be done as single statement.
        'single_trait_insert_per_statement' => true,
        // Fix whitespace after a semicolon.
        'space_after_semicolon' => ['remove_in_empty_for_expressions' => true],
        // Parentheses must be declared using the configured whitespace.
        'spaces_inside_parentheses' => true,
        // Increment and decrement operators should be used if possible.
        'standardize_increment' => true,
        // Replace all `<>` with `!=`.
        'standardize_not_equals' => true,
        // Each statement must be indented.
        'statement_indentation' => true,
        // Lambdas not (indirectly) referencing `$this` must be declared `static`.
        'static_lambda' => true,
        // A case should be followed by a colon and not a semicolon.
        'switch_case_semicolon_to_colon' => true,
        // Removes extra spaces between colon and case value.
        'switch_case_space' => true,
        // Switch case must not be ended with `continue` but with `break`.
        'switch_continue_to_break' => true,
        // Standardize spaces around ternary operator.
        'ternary_operator_spaces' => true,
        // Use the Elvis operator `?:` where possible.
        'ternary_to_elvis_operator' => true,
        // Use `null` coalescing operator `??` where possible.
        'ternary_to_null_coalescing' => true,
        // Arguments lists, array destructuring lists, arrays that are multi-line, `match`-lines and parameters lists must have a trailing comma.
        'trailing_comma_in_multiline' => true,
        // Arrays should be formatted like function/method arguments, without leading or trailing single line space.
        'trim_array_spaces' => true,
        // Ensure single space between a variable and its type declaration in function arguments and properties.
        'type_declaration_spaces' => true,
        // A single space or none should be around union type and intersection type operators.
        'types_spaces' => true,
        // Unary operators should be placed adjacent to their operands.
        'unary_operator_spaces' => true,
        // Visibility MUST be declared on all properties and methods; `abstract` and `final` MUST be declared before the visibility; `static` MUST be declared after the visibility.
        'visibility_required' => true,
        // In array declaration, there MUST be a whitespace after each comma.
        'whitespace_after_comma_in_array' => true,
        // Write conditions in Yoda style (`true`), non-Yoda style (`['equal' => false, 'identical' => false, 'less_and_greater' => false]`) or ignore those conditions (`null`) based on configuration.
        'yoda_style' => ['always_move_variable' => false,'equal' => false,'identical' => false,'less_and_greater' => null],
    ])
    ->setFinder((new PhpCsFixer\Finder())
        ->in(__DIR__)
        // ->exclude([
        //     'folder-to-exclude',
        // ])
        // ->append([
        //     'file-to-include',
        // ])
    )
;
