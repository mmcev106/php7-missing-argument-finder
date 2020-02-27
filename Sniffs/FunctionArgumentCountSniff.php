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
        '+',
        ',',
        'return',
        'PrintFooterExt',
        'PrintHeaderExt',
        '=',
        'exit',
        'elseif',
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
        'escape' => 1
    ];

    private $calls = [];
    private $currentFunctionName;

    function register()
    {
        $this->IGNORED = array_flip($this->IGNORED);

        register_shutdown_function(function(){
            $errors = [];

            foreach($this->calls as $functionName=>$callInfo){
                $minArgs = @$this->definitions[$functionName];
                if($minArgs === null){
                    if(substr($functionName, 0, 1) === '$'){
                        // Assume this is a callable variable.
                        // We have no way of knowing the expected number of arguments, so skip it.
                        continue;
                    }

                    $errors[] = "The '$functionName' function was called but not defined here: " . $callInfo['location'];
                }
                else if($callInfo['args'] < $minArgs){
                    $errors[] = "Parameters missing for a call to the '$functionName' function here: " . $callInfo['location'];
                }
            }

            echo implode("\n", $errors) . "\n";
        });

        return [T_FUNCTION, T_OPEN_PARENTHESIS];
    }

    function process(File $file, $position)
    {
        $getDefinedFunctionName = function($position) use ($file){
            do {
                $position++;
                $content = $file->getTokens()[$position]['content'];
            } while(in_array($content, [' ', '&']));
            
            return $content;
        };

        $getCalledFunctionName = function($position) use ($file){
            do {
                $position--;
                $content = $file->getTokens()[$position]['content'];
            } while($content === ' ');

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
                if($content === '('){
                    $nestingLevel++;
                    continue;
                }
                else if($content === ')' && $nestingLevel > 0){
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
                $this->definitions[$this->currentFunctionName] = $minArgs;
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

                $callInfo = @$this->calls[$functionName];
                $oldMin = $callInfo['args'];
                if($oldMin !== null && $oldMin < $minArgs){
                    $minArgs = $oldMin;
                }

                $this->calls[$functionName] = [
                    'args' => $minArgs,
                    'location' => $file->path . ':' . $file->getTokens()[$position]['line']
                ];
            }
        }        
    }
}