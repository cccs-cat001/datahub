import React from 'react';

import { TestResultsList } from '@app/entity/shared/tabs/Dataset/Governance/TestResultsList';
import { TestResultsSummary } from '@app/entity/shared/tabs/Dataset/Governance/TestResultsSummary';

import { TestResult } from '@types';

type Props = {
    passing: Array<TestResult>;
    failing: Array<TestResult>;
};

export const TestResults = ({ passing, failing }: Props) => {
    const filteredPassing = passing.filter((testResult) => testResult.test !== null);
    const filteredFailing = failing.filter((testResult) => testResult.test !== null);
    const totalTests = filteredPassing.length + filteredFailing.length;

    return (
        <>
            <TestResultsSummary
                summary={{
                    passing: filteredPassing.length,
                    failing: filteredFailing.length,
                    total: totalTests,
                }}
            />
            {totalTests > 0 && (
                <TestResultsList title="Governance Test Results" results={[...filteredFailing, ...filteredPassing]} />
            )}
        </>
    );
};
