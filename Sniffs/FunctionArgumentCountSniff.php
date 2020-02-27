<?php

// require_once '/cygdrive/c/Users/mceverm/UniServerZ/www/redcap_connect.php';

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

class DisallowedFunctionSniff implements Sniff
{
    private $IGNORED = [
        'while',
        'unset',
        'initializeJavascriptModuleObject',
        'getModuleName',
        'foreach',
        'getProjectsWithModuleEnabled',
        'if',
        'Exception',
        'for',
        'getProjectId',
        '.',
        'use',
        'catch',
        'fetch_assoc',
        'getMessage',
        'getTraceAsString',
        'getProject',
        'getUsers',
        'isSuperUser',
        'getEmail',
        'empty',
        'requireProjectId',
        '&&',
        'isset',
        'array',
        'Array',
        '+',
        ',',
        'return',
        'PrintFooterExt',
        'PrintHeaderExt',
        '=',
        'exit',
        'elseif',
        'switch',
        'list',

    ];

    private $definitions = [
        'getUrl' => 1,
        'getSubSettings' => 1,
        'getData' => 1,
        'getProjectSetting' => 1,
        'getSQLInClause' => 2,
        'db_real_escape_string' => 1,
        'query' => 1,
        'setProjectSetting' => 2,
        'email' => 4,
        'db_fetch_assoc' => 1,
        'queryLogs' => 1,
        'db_escape' => 1,
        'lock' => 1,
        'saveData' => 2,
        'getMetadata' => 1,
        'removeProjectSetting' => 1,
        'oci_fetch_assoc' => 1,
        'prep_implode' => 1,
        'redirect' => 1,
        'getTableColumns' => 1,
        'js_escape' => 1,
        'td' => 1,
        'escape' => 1,
        'Libraries' => 1,
        'Rect' => 4,
        'Cell' => 5,
        'MultiCell' => 4,
        'SetTextColor' => 3,
        'setPageBuffer' => 3,
        'SetAutoPageBreak' => 1,
        'getPDF' => 2,
        'exportRecords' => 4,
        'assertCount' => 2,
        'assertGreaterThan' => 2,
        'assertEquals' => 2,
        'assertSame' => 2,
        'AddAttachment' => 1,
        'SetFrom' => 1,
        'addIdentifier' => 1,
        'pre_query' => 1,
        'deleteRecords' => 1,
    ];

    private $calls = [];
    private $currentFunctionName;

    function register()
    {
        $this->IGNORED = array_flip($this->IGNORED);

        register_shutdown_function(function(){
            foreach($this->calls as $functionName=>$calls){
                $lastArgs = null;
                foreach($calls as $callInfo){
                    $args = $callInfo['args'];
                    if($lastArgs != null){
                        if($args != $lastArgs){
                            $this->handleArgMismatch($functionName, $callInfo);
                            break;
                        }
                    }

                    $lastArgs = $args;
                }
            }
        });

        return [T_FUNCTION, T_OPEN_PARENTHESIS];
    }

    private function handleArgMismatch($functionName, $callInfo){
        $minArgs = @$this->definitions[$functionName];
        if($minArgs === null){
            if(substr($functionName, 0, 1) === '$'){
                // Assume this is a callable variable.
                // We have no way of knowing the expected number of arguments, so skip it.
                return;
            }

            echo "The '$functionName' function was called but not defined here: " . $callInfo['location'] . "\n";
        }
        else if($callInfo['args'] < $minArgs){
            echo "Parameters missing for a call to the '$functionName' function here: " . $callInfo['location'] . "\n";
        }
    }

    function process(File $file, $position)
    {
        $getDefinedFunctionName = function($position) use ($file){
            do {
                $position++;
                $content = trim($file->getTokens()[$position]['content']);
            } while(in_array($content, ['', '&']));

           return $content;
        };

        $getCalledFunctionName = function($position) use ($file){
            do {
                $position--;
                $content = trim($file->getTokens()[$position]['content']);
            } while($content === '');

            $functionName = $content;

            do {
                if($position === 0 ){
                    break;
                }

                $position--;
                $content = $file->getTokens()[$position]['content'];
            } while($content !== ' ');

            $isConstructorCall = false;
            if($position !== 0){
                $position--;
                $content = $file->getTokens()[$position]['content'];
                $isConstructorCall = $content === 'new';
            }

            return [$functionName, $isConstructorCall];
        };
        
        $getMinArgs = function($position) use ($file){
            $argCode = '';
            $subtractOne = false;
            $nestingLevel = 0;
            while(true){
                $position++;
                $content = $file->getTokens()[$position]['content'];
                if(in_array($content, ['(', '['])){
                    $nestingLevel++;
                    continue;
                }
                else if(in_array($content, [')', ']']) && $nestingLevel > 0){
                    $nestingLevel--;
                    continue;
                }

                if(in_array($content, ['=', ')'])){
                    if($content === '='){
                        $subtractOne = true;
                    }

                    break;
                }

                if($nestingLevel === 0){
                    $argCode .= $content;
                }
                else{
                    $argCode .= ' ';
                }
            }

            $args = explode(',', $argCode);

            $count = count($args);
            if($subtractOne){
                $count--;
            }

            return $count;
        };

        $token =  $file->getTokens()[$position];
        $type = $token['type'];

        if($type === 'T_FUNCTION'){
            $this->currentFunctionName = $getDefinedFunctionName($position);
        }
        else if ($type === 'T_OPEN_PARENTHESIS'){
            $minArgs = $getMinArgs($position);

            if($this->currentFunctionName){
                $existingArgs = @$this->definitions[$this->currentFunctionName];

                if($existingArgs === null || $existingArgs > $minArgs){
                    $this->definitions[$this->currentFunctionName] = $minArgs;
                }

                $this->currentFunctionName = null;
            }
            else{
                list($functionName, $isConstructorCall) = $getCalledFunctionName($position);
                if(
                    function_exists($functionName)
                    ||
                    isset($this->IGNORED[$functionName])
                    ||
                    $isConstructorCall
                ){
                    return;
                }
                else if($functionName === 'function'){
                    // This is an anonymous function definition.
                    $functionName = $getDefinedFunctionName($position);
                    $this->definitions['$' . $functionName] = $minArgs;
                }

                $this->calls[$functionName][] = [
                    'args' => $minArgs,
                    'location' => $file->path . ':' . $file->getTokens()[$position]['line']
                ];
            }
        }        
    }
}