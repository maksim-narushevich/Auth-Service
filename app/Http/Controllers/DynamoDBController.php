<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use MNarushevich\AuditLogs\Services\AWS\DynamoDBService;

class DynamoDBController extends Controller
{
    public function __construct(private DynamoDBService $dynamoDBService) {}

    public function createTable()
    {
        $this->dynamoDBService->createTable();

        config('auditlogs.dynamodb.endpoint');

        return response()->json(['message' => 'Table created successfully']);
    }

    public function store(Request $request)
    {
        $this->dynamoDBService->insertItem(data: $request->all());

        return response()->json([
            'message' => 'Item inserted successfully',
        ]);
    }

    public function show($id)
    {
        return response()->json($this->dynamoDBService->getItem(id: $id));
    }

    public function destroy($id)
    {
        $this->dynamoDBService->deleteItem(id: $id);

        return response()->json(['message' => 'Item deleted successfully']);
    }
}
