import { blockchainTests, getRandomInteger, getRandomPortion } from '@0x/contracts-test-utils';
import { BigNumber } from '@0x/utils';

import { MetaTransactionsContract, ZeroExContract } from '../wrappers';
import { fullMigrateAsync } from '../utils/migration';

blockchainTests.resets.only('MetaTransactions feature', env => {
    let owner: string;
    let zeroEx: ZeroExContract;
    let feature: MetaTransactionsContract;

    before(async () => {
        [owner] = await env.getAccountAddressesAsync();
        zeroEx = await fullMigrateAsync(owner, env.provider, env.txDefaults);
        feature = new MetaTransactionsContract(zeroEx.address, env.provider, env.txDefaults);
    });
});
